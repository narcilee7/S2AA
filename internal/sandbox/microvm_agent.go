package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"

	"github.com/mdlayher/vsock"
)

// agentClient communicates with the sandbox-agent running inside a microVM.
type agentClient struct {
	baseURL    string
	httpClient *http.Client
}

// newAgentClientVSOCK creates an HTTP client that dials the guest via AF_VSOCK.
func newAgentClientVSOCK(guestCID uint32, guestPort uint32) *agentClient {
	return &agentClient{
		baseURL: fmt.Sprintf("http://%d:%d", guestCID, guestPort),
		httpClient: &http.Client{
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return vsock.Dial(guestCID, guestPort, nil)
				},
			},
			Timeout: 30 * time.Second,
		},
	}
}

// newAgentClientTCP creates an HTTP client for local testing via TCP forwarding.
func newAgentClientTCP(host string) *agentClient {
	return &agentClient{
		baseURL:    "http://" + host,
		httpClient: &http.Client{Timeout: 30 * time.Second},
	}
}

func (c *agentClient) doJSON(ctx context.Context, method, path string, reqBody, respBody interface{}) error {
	var body io.Reader
	if reqBody != nil {
		data, err := json.Marshal(reqBody)
		if err != nil {
			return err
		}
		body = bytes.NewReader(data)
	}

	req, err := http.NewRequestWithContext(ctx, method, c.baseURL+path, body)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("agent request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("agent returned %d: %s", resp.StatusCode, string(b))
	}

	if respBody != nil {
		return json.NewDecoder(resp.Body).Decode(respBody)
	}
	return nil
}

func (c *agentClient) Execute(ctx context.Context, req AgentExecuteRequest) (*AgentExecuteResponse, error) {
	var resp AgentExecuteResponse
	err := c.doJSON(ctx, http.MethodPost, "/execute", req, &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *agentClient) Cancel(ctx context.Context, req AgentCancelRequest) (*AgentCancelResponse, error) {
	var resp AgentCancelResponse
	err := c.doJSON(ctx, http.MethodPost, "/cancel", req, &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *agentClient) ReadFile(ctx context.Context, path string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/read?path="+path, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	return io.ReadAll(resp.Body)
}

func (c *agentClient) WriteFile(ctx context.Context, req AgentWriteFileRequest) (*AgentFileResponse, error) {
	var resp AgentFileResponse
	err := c.doJSON(ctx, http.MethodPost, "/write", req, &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *agentClient) ListFiles(ctx context.Context, path string) (*AgentListFilesResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/list?path="+path, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var result AgentListFilesResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *agentClient) DeleteFile(ctx context.Context, path string) (*AgentFileResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/delete?path="+path, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var result AgentFileResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *agentClient) ExposePort(ctx context.Context, req AgentPortRequest) (*AgentPortResponse, error) {
	var resp AgentPortResponse
	err := c.doJSON(ctx, http.MethodPost, "/port", req, &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

func (c *agentClient) Status(ctx context.Context) (*AgentStatusResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/status", nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var result AgentStatusResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}
	return &result, nil
}

func (c *agentClient) Health(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.baseURL+"/health", nil)
	if err != nil {
		return err
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("health check failed: %d", resp.StatusCode)
	}
	return nil
}
