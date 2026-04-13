package sandbox

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/narcilee7/agent-sandbox/internal/utils"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// secureSandbox provides remote sandbox execution via gRPC.
type secureSandbox struct {
	id         string
	limits     *ResourceLimits
	caps       *Capabilities
	endpoint   string
	timeout    time.Duration
	grpcConn   *grpc.ClientConn
	grpcClient SandboxServiceClient
	httpClient *http.Client
	mutex      sync.RWMutex
	state      string
	createdAt  time.Time
	connected  bool
}

// SandboxServiceClient is interface for remote sandbox gRPC service.
// TODO: Define actual gRPC service and generate client stubs.
type SandboxServiceClient interface {
	ExecuteCommand(ctx context.Context, req *ExecuteRequest) (*ExecuteResponse, error)
	CancelCommand(ctx context.Context, req *CancelRequest) (*CancelResponse, error)
	GetStatus(ctx context.Context, req *StatusRequest) (*StatusResponse, error)
}

// ExecuteRequest is request for executing a command.
type ExecuteRequest struct {
	SandboxID    string            `json:"sandbox_id"`
	Command      string            `json:"command"`
	Args         []string          `json:"args"`
	Env          map[string]string `json:"env"`
	WorkingDir   string            `json:"working_dir"`
	Stdin        []byte            `json:"stdin"`
	Timeout      int64             `json:"timeout_ms"`
	Limits       *ResourceLimits   `json:"limits"`
	Capabilities *Capabilities     `json:"capabilities"`
}

// ExecuteResponse is response from command execution.
type ExecuteResponse struct {
	CommandID  string `json:"command_id"`
	Success    bool   `json:"success"`
	ExitCode   int    `json:"exit_code"`
	Stdout     []byte `json:"stdout"`
	Stderr     []byte `json:"stderr"`
	Error      string `json:"error,omitempty"`
	DurationMs int64  `json:"duration_ms"`
}

// CancelRequest is request to cancel a command.
type CancelRequest struct {
	CommandID string `json:"command_id"`
}

// CancelResponse is response from cancel operation.
type CancelResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message,omitempty"`
}

// StatusRequest is request for sandbox status.
type StatusRequest struct {
	SandboxID string `json:"sandbox_id"`
}

// StatusResponse is response from status request.
type StatusResponse struct {
	State       string `json:"state"`
	ActiveTasks int    `json:"active_tasks"`
	UptimeMs    int64  `json:"uptime_ms"`
}

// newSecureSandbox creates a new L4 secure sandbox.
func newSecureSandbox(
	limits *ResourceLimits,
	caps *Capabilities,
	endpoint string,
) (*secureSandbox, error) {
	if endpoint == "" {
		return nil, fmt.Errorf("remote endpoint required for L4 sandbox")
	}

	if limits == nil {
		limits = DefaultResourceLimits(LevelSecure)
	}
	if caps == nil {
		caps = DefaultCapabilities(LevelSecure)
	}

	sandbox := &secureSandbox{
		id:        utils.GenerateID(),
		limits:    limits,
		caps:      caps,
		endpoint:  endpoint,
		timeout:   10 * time.Second, // Default gRPC timeout
		state:     "idle",
		createdAt: time.Now().UTC(),
		connected: false,
	}

	// Initialize HTTP client as fallback
	sandbox.httpClient = &http.Client{
		Timeout: 30 * time.Second,
	}

	return sandbox, nil
}

// Connect establishes connection to remote sandbox service.
func (s *secureSandbox) Connect(ctx context.Context) error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.connected {
		return nil
	}

	// Try to establish gRPC connection
	grpcConn, err := grpc.DialContext(ctx, s.endpoint, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err == nil {
		s.grpcConn = grpcConn
		s.connected = true
		return nil
	}

	// gRPC connection failed, will use HTTP fallback
	s.grpcConn = nil
	s.grpcClient = nil
	s.connected = false
	return fmt.Errorf("gRPC connection failed, will use HTTP fallback: %w", err)
}

// Disconnect closes connection to remote sandbox service.
func (s *secureSandbox) Disconnect() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.grpcConn != nil {
		err := s.grpcConn.Close()
		s.grpcConn = nil
		s.grpcClient = nil
		s.connected = false
		return err
	}

	s.connected = false
	return nil
}

// Execute executes a command remotely.
func (s *secureSandbox) Execute(ctx context.Context, cmd Command) (*Result, error) {
	s.mutex.Lock()
	s.state = "running"
	s.mutex.Unlock()
	defer func() {
		s.mutex.Lock()
		s.state = "idle"
		s.mutex.Unlock()
	}()

	// Ensure connection
	if err := s.Connect(ctx); err != nil {
		// Fall back to HTTP execution
		return s.executeViaHTTP(ctx, cmd)
	}

	// Use gRPC execution
	if s.grpcClient != nil {
		return s.executeViaGRPC(ctx, cmd)
	}

	// Fall back to HTTP execution
	return s.executeViaHTTP(ctx, cmd)
}

// executeViaGRPC executes command via gRPC.
func (s *secureSandbox) executeViaGRPC(ctx context.Context, cmd Command) (*Result, error) {
	req := &ExecuteRequest{
		SandboxID:    s.id,
		Command:      cmd.Exec,
		Args:         cmd.Args,
		Env:          convertEnvSlice(cmd.Env),
		WorkingDir:   cmd.WorkingDir,
		Stdin:        cmd.Stdin,
		Timeout:      cmd.Timeout.Milliseconds(),
		Limits:       s.limits,
		Capabilities: s.caps,
	}

	resp, err := s.grpcClient.ExecuteCommand(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("gRPC execute command failed: %w", err)
	}

	return &Result{
		CommandID:     cmd.ID,
		ExitCode:      resp.ExitCode,
		Success:       resp.Success,
		Stdout:        resp.Stdout,
		Stderr:        resp.Stderr,
		Duration:      time.Duration(resp.DurationMs) * time.Millisecond,
		SandboxID:     s.id,
		SecurityLevel: LevelSecure,
		Metrics: &ExecutionMetrics{
			CPUMilliseconds: resp.DurationMs,
		},
	}, nil
}

// executeViaHTTP executes command via HTTP REST API.
func (s *secureSandbox) executeViaHTTP(ctx context.Context, cmd Command) (*Result, error) {
	startTime := time.Now()

	// Prepare request body
	req := ExecuteRequest{
		SandboxID:    s.id,
		Command:      cmd.Exec,
		Args:         cmd.Args,
		Env:          convertEnvSlice(cmd.Env),
		WorkingDir:   cmd.WorkingDir,
		Stdin:        cmd.Stdin,
		Timeout:      cmd.Timeout.Milliseconds(),
		Limits:       s.limits,
		Capabilities: s.caps,
	}

	reqBody, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal request: %w", err)
	}

	// Create HTTP request
	httpReq, err := http.NewRequestWithContext(ctx, "POST", s.buildEndpointURL("/execute"), nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-Sandbox-ID", s.id)
	httpReq.Body = io.NopCloser(bytes.NewReader(reqBody))

	// Send request
	httpResp, err := s.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failed: %w", err)
	}
	defer httpResp.Body.Close()

	// Read response
	respBody, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response: %w", err)
	}

	if httpResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP error: %d, body: %s", httpResp.StatusCode, string(respBody))
	}

	// Parse response
	var resp ExecuteResponse
	if err := json.Unmarshal(respBody, &resp); err != nil {
		return nil, fmt.Errorf("failed to parse response: %w", err)
	}

	duration := time.Since(startTime)

	return &Result{
		CommandID:     cmd.ID,
		ExitCode:      resp.ExitCode,
		Success:       resp.Success,
		Stdout:        resp.Stdout,
		Stderr:        resp.Stderr,
		Duration:      duration,
		SandboxID:     s.id,
		SecurityLevel: LevelSecure,
		Metrics: &ExecutionMetrics{
			CPUMilliseconds: resp.DurationMs,
		},
	}, nil
}

// ExecuteStreaming executes a command with streaming output.
func (s *secureSandbox) ExecuteStreaming(
	ctx context.Context,
	cmd Command,
	onStdout func(data []byte),
	onStderr func(data []byte),
	onProgress func(progress float64),
) (*Result, error) {
	s.mutex.Lock()
	s.state = "running"
	s.mutex.Unlock()
	defer func() {
		s.mutex.Lock()
		s.state = "idle"
		s.mutex.Unlock()
	}()

	// For simplicity, delegate to Execute for now
	// TODO: Implement true streaming via WebSocket or gRPC streaming
	result, err := s.Execute(ctx, cmd)
	if err != nil {
		return nil, err
	}

	// Callback with buffered output
	if onStdout != nil && len(result.Stdout) > 0 {
		onStdout(result.Stdout)
	}
	if onStderr != nil && len(result.Stderr) > 0 {
		onStderr(result.Stderr)
	}

	return result, nil
}

// Cancel cancels a running command.
func (s *secureSandbox) Cancel(commandID string) error {
	ctx, cancel := context.WithTimeout(context.Background(), s.timeout)
	defer cancel()

	// Try gRPC first
	if s.grpcClient != nil {
		req := &CancelRequest{CommandID: string(commandID)}
		_, err := s.grpcClient.CancelCommand(ctx, req)
		if err == nil {
			return nil
		}
		// Fall through to HTTP
	}

	// HTTP fallback
	req := CancelRequest{CommandID: string(commandID)}
	reqBody, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to marshal cancel request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, "POST", s.buildEndpointURL("/cancel"), nil)
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-Sandbox-ID", s.id)
	httpReq.Body = io.NopCloser(bytes.NewReader(reqBody))

	httpResp, err := s.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("HTTP cancel request failed: %w", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		return fmt.Errorf("HTTP cancel failed: %d", httpResp.StatusCode)
	}

	return nil
}

// Cleanup cleans up sandbox resources.
func (s *secureSandbox) Cleanup() error {
	return s.Disconnect()
}

// Info returns sandbox information.
func (s *secureSandbox) Info() SandboxInfo {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	activeTasks := 0

	// Try to get remote status if connected
	if s.connected {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		if s.grpcClient != nil {
			req := &StatusRequest{SandboxID: s.id}
			resp, err := s.grpcClient.GetStatus(ctx, req)
			if err == nil {
				activeTasks = resp.ActiveTasks
			}
		}
	}

	return SandboxInfo{
		ID:          s.id,
		Level:       LevelSecure,
		State:       s.state,
		CreatedAt:   s.createdAt,
		ActiveTasks: activeTasks,
	}
}

// Level returns security level.
func (s *secureSandbox) Level() SecurityLevel {
	return LevelSecure
}

// Filesystem returns a legacy host filesystem accessor.
func (s *secureSandbox) Filesystem() Filesystem {
	return newLegacyFilesystem("")
}

// PortForwarder returns a no-op port forwarder.
func (s *secureSandbox) PortForwarder() PortForwarder {
	return defaultNoopPortForwarder
}

// Endpoint returns remote sandbox endpoint.
func (s *secureSandbox) Endpoint() string {
	return s.endpoint
}

// Connected returns whether connected to remote service.
func (s *secureSandbox) Connected() bool {
	s.mutex.RLock()
	defer s.mutex.RUnlock()
	return s.connected
}

// buildEndpointURL builds full URL for HTTP endpoint.
func (s *secureSandbox) buildEndpointURL(path string) string {
	return s.endpoint + path
}

// convertEnvSlice converts env slice to map.
func convertEnvSlice(env []string) map[string]string {
	result := make(map[string]string)
	for _, e := range env {
		for i := 0; i < len(e); i++ {
			if e[i] == '=' {
				result[e[:i]] = e[i+1:]
				break
			}
		}
	}
	return result
}
