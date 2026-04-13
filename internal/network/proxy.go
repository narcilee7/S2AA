package network

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/narcilee7/S2AA/internal/audit"
)

// AllowFunc decides whether a connection to (host, port) is allowed.
type AllowFunc func(host string, port int) bool

// Proxy is a lightweight HTTP/HTTPS CONNECT proxy with policy enforcement.
type Proxy struct {
	addr      string
	allow     AllowFunc
	auditor   audit.Auditor
	sandboxID string
	listener  net.Listener
	mu        sync.RWMutex
	closed    bool
}

// NewProxy creates a new network proxy for a sandbox.
func NewProxy(addr string, allow AllowFunc, auditor audit.Auditor, sandboxID string) *Proxy {
	if auditor == nil {
		auditor = audit.DefaultNoOp()
	}
	if allow == nil {
		allow = func(string, int) bool { return true }
	}
	return &Proxy{
		addr:      addr,
		allow:     allow,
		auditor:   auditor,
		sandboxID: sandboxID,
	}
}

// Start begins listening for proxy connections.
func (p *Proxy) Start() error {
	ln, err := net.Listen("tcp", p.addr)
	if err != nil {
		return err
	}
	p.listener = ln
	p.addr = ln.Addr().String()
	go p.serve()
	return nil
}

// Addr returns the actual listen address.
func (p *Proxy) Addr() string {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.addr
}

// Stop shuts down the proxy listener.
func (p *Proxy) Stop() error {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.closed {
		return nil
	}
	p.closed = true
	if p.listener != nil {
		return p.listener.Close()
	}
	return nil
}

func (p *Proxy) serve() {
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			p.mu.RLock()
			closed := p.closed
			p.mu.RUnlock()
			if closed {
				return
			}
			continue
		}
		go p.handleConn(conn)
	}
}

func (p *Proxy) handleConn(clientConn net.Conn) {
	defer clientConn.Close()

	reader := bufio.NewReader(clientConn)
	req, err := http.ReadRequest(reader)
	if err != nil {
		return
	}

	if req.Method == http.MethodConnect {
		p.handleConnect(clientConn, req)
		return
	}

	p.handleHTTP(clientConn, req, reader)
}

func (p *Proxy) handleHTTP(clientConn net.Conn, req *http.Request, reader *bufio.Reader) {
	host := req.URL.Host
	if host == "" {
		host = req.Host
	}

	if !p.allowed(host) {
		p.writeDenied(clientConn, req)
		return
	}

	dialAddr := host
	if !strings.Contains(dialAddr, ":") {
		dialAddr = net.JoinHostPort(dialAddr, "80")
	}

	serverConn, err := net.Dial("tcp", dialAddr)
	if err != nil {
		p.writeError(clientConn, http.StatusBadGateway, err)
		return
	}
	defer serverConn.Close()

	// Forward the original request.
	if err := req.Write(serverConn); err != nil {
		return
	}

	p.pipe(clientConn, serverConn, host)
}

func (p *Proxy) handleConnect(clientConn net.Conn, req *http.Request) {
	host := req.Host
	if !p.allowed(host) {
		clientConn.Write([]byte("HTTP/1.1 403 Forbidden\r\n\r\n"))
		return
	}

	serverConn, err := net.Dial("tcp", host)
	if err != nil {
		clientConn.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer serverConn.Close()

	clientConn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
	p.pipe(clientConn, serverConn, host)
}

func (p *Proxy) pipe(client, server net.Conn, host string) {
	errChan := make(chan error, 2)
	copy := func(dst, src net.Conn) {
		_, err := io.Copy(dst, src)
		errChan <- err
	}

	go copy(server, client)
	go copy(client, server)

	<-errChan
	client.Close()
	server.Close()
	<-errChan
}

func (p *Proxy) allowed(addr string) bool {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
		portStr = "0"
	}
	port, _ := strconv.Atoi(portStr)

	allowed := p.allow(host, port)

	p.auditor.LogNetwork(audit.NetworkConn{
		SandboxID: p.sandboxID,
		Host:      host,
		Port:      port,
		Allowed:   allowed,
		Timestamp: time.Now().UTC(),
	})

	return allowed
}

func (p *Proxy) writeDenied(w net.Conn, req *http.Request) {
	resp := &http.Response{
		StatusCode: http.StatusForbidden,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader("Forbidden by sandbox policy")),
	}
	resp.Write(w)
}

func (p *Proxy) writeError(w net.Conn, code int, err error) {
	resp := &http.Response{
		StatusCode: code,
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(err.Error())),
	}
	resp.Write(w)
}

// EnsureProxyEnv returns environment variables that force HTTP/HTTPS traffic
// through the given proxy address.
func EnsureProxyEnv(env []string, proxyURL string) []string {
	set := func(key, value string) {
		found := false
		prefix := key + "="
		for i, e := range env {
			if strings.HasPrefix(e, prefix) {
				env[i] = prefix + value
				found = true
				break
			}
		}
		if !found {
			env = append(env, prefix+value)
		}
	}
	set("HTTP_PROXY", proxyURL)
	set("HTTPS_PROXY", proxyURL)
	set("http_proxy", proxyURL)
	set("https_proxy", proxyURL)
	set("NO_PROXY", "localhost,127.0.0.1")
	return env
}
