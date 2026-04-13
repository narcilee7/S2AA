package sandbox

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/narcilee7/S2AA/api/sandboxpb"
	"github.com/narcilee7/S2AA/internal/audit"
	"github.com/narcilee7/S2AA/internal/network"
	"github.com/narcilee7/S2AA/internal/utils"
)

// microvmSandbox provides hardware-level isolation via Firecracker microVMs.
// It delegates execution, filesystem, and port operations to a guest agent
// running inside the VM and reachable over vsock.
type microvmSandbox struct {
	id             string
	limits         *ResourceLimits
	caps           *Capabilities
	baseDir        string
	workspace      string
	state          string
	createdAt      time.Time
	mutex          sync.RWMutex
	running        int
	guestCID       uint32
	guestPort      uint32
	apiSocket      string // Firecracker API unix socket path
	vmPID          int
	agent          *agentClient
	secretProvider SecretProvider
	auditor        audit.Auditor
	persistent     bool
	proxy          *network.Proxy
}

// firecrackerConfig is the JSON payload sent to Firecracker's API.
type firecrackerConfig struct {
	BootSource    bootSource  `json:"boot_source"`
	Drives        []drive     `json:"drives"`
	MachineConfig machineCfg  `json:"machine_config"`
	Vsock         vsockDevice `json:"vsock"`
}

type bootSource struct {
	KernelImagePath string `json:"kernel_image_path"`
	BootArgs        string `json:"boot_args"`
}

type drive struct {
	DriveID      string `json:"drive_id"`
	PathOnHost   string `json:"path_on_host"`
	IsRootDevice bool   `json:"is_root_device"`
	IsReadOnly   bool   `json:"is_read_only"`
}

type machineCfg struct {
	VcpuCount  int `json:"vcpu_count"`
	MemSizeMib int `json:"mem_size_mib"`
}

type vsockDevice struct {
	GuestCID int    `json:"guest_cid"`
	UDSPath  string `json:"uds_path"`
}

// newMicroVMSandbox creates a new Firecracker-backed sandbox.
func newMicroVMSandbox(
	limits *ResourceLimits,
	caps *Capabilities,
	baseDir string,
	secretProvider SecretProvider,
	auditor audit.Auditor,
) (*microvmSandbox, error) {
	id := utils.GenerateID()
	workspace := filepath.Join(baseDir, "workspaces", id)
	if err := os.MkdirAll(workspace, 0755); err != nil {
		return nil, fmt.Errorf("failed to create workspace: %w", err)
	}

	if limits == nil {
		limits = DefaultResourceLimits(LevelIsolated)
	}
	if caps == nil {
		caps = DefaultCapabilities(LevelIsolated)
	}
	if auditor == nil {
		auditor = audit.DefaultNoOp()
	}

	// TODO: assign a unique guest CID without collisions.
	guestCID := uint32(3 + time.Now().UnixNano()%10000)

	s := &microvmSandbox{
		id:             id,
		limits:         limits,
		caps:           caps,
		baseDir:        baseDir,
		workspace:      workspace,
		state:          "idle",
		createdAt:      time.Now().UTC(),
		guestCID:       guestCID,
		guestPort:      8080,
		apiSocket:      filepath.Join(workspace, "firecracker.sock"),
		secretProvider: secretProvider,
		auditor:        auditor,
		persistent:     false,
	}

	return s, nil
}

// startVM bootstraps the Firecracker microVM and connects to the guest agent.
func (s *microvmSandbox) startVM(ctx context.Context) error {
	if _, err := exec.LookPath("firecracker"); err != nil {
		return fmt.Errorf("firecracker binary not found: %w", err)
	}

	kernelPath := os.Getenv("FIRECRACKER_KERNEL")
	rootfsPath := os.Getenv("FIRECRACKER_ROOTFS")
	if kernelPath == "" || rootfsPath == "" {
		return fmt.Errorf("FIRECRACKER_KERNEL and FIRECRACKER_ROOTFS must be set")
	}

	cmd := exec.CommandContext(ctx, "firecracker", "--api-sock", s.apiSocket)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start firecracker: %w", err)
	}
	s.vmPID = cmd.Process.Pid

	for i := 0; i < 50; i++ {
		if _, err := os.Stat(s.apiSocket); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	fcCfg := firecrackerConfig{
		BootSource: bootSource{
			KernelImagePath: kernelPath,
			BootArgs:        "console=ttyS0 reboot=k panic=1 pci=off",
		},
		Drives: []drive{
			{
				DriveID:      "rootfs",
				PathOnHost:   rootfsPath,
				IsRootDevice: true,
				IsReadOnly:   false,
			},
		},
		MachineConfig: machineCfg{
			VcpuCount:  int(s.limits.CPUMax),
			MemSizeMib: int(s.limits.MemoryBytes / (1024 * 1024)),
		},
		Vsock: vsockDevice{
			GuestCID: int(s.guestCID),
			UDSPath:  filepath.Join(s.workspace, "vsock.sock"),
		},
	}

	if err := s.fcPut(ctx, "/machine-config", fcCfg.MachineConfig); err != nil {
		return fmt.Errorf("failed to configure machine: %w", err)
	}
	if err := s.fcPut(ctx, "/drives/rootfs", fcCfg.Drives[0]); err != nil {
		return fmt.Errorf("failed to configure drive: %w", err)
	}
	if err := s.fcPut(ctx, "/boot-source", fcCfg.BootSource); err != nil {
		return fmt.Errorf("failed to configure boot source: %w", err)
	}
	if err := s.fcPut(ctx, "/vsock", fcCfg.Vsock); err != nil {
		return fmt.Errorf("failed to configure vsock: %w", err)
	}
	if err := s.fcAction(ctx, "InstanceStart"); err != nil {
		return fmt.Errorf("failed to start instance: %w", err)
	}

	agent, err := newAgentClientVSOCK(s.guestCID, s.guestPort)
	if err != nil {
		return fmt.Errorf("failed to create agent client: %w", err)
	}
	s.agent = agent
	for i := 0; i < 60; i++ {
		if err := s.agent.Health(ctx); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	allowFunc := makeAllowFunc(s.caps)
	s.proxy = network.NewProxy("127.0.0.1:0", allowFunc, s.auditor, s.id)
	if err := s.proxy.Start(); err != nil {
		return fmt.Errorf("failed to start network proxy: %w", err)
	}

	return nil
}

func (s *microvmSandbox) fcPut(ctx context.Context, path string, body interface{}) error {
	data, err := json.Marshal(body)
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, "curl", "--unix-socket", s.apiSocket,
		"-X", "PUT", "http://localhost"+path,
		"-H", "Content-Type: application/json",
		"-d", string(data),
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("fcPut %s failed: %w, output: %s", path, err, string(out))
	}
	return nil
}

func (s *microvmSandbox) fcAction(ctx context.Context, action string) error {
	payload := map[string]string{"action_type": action}
	data, _ := json.Marshal(payload)
	cmd := exec.CommandContext(ctx, "curl", "--unix-socket", s.apiSocket,
		"-X", "PUT", "http://localhost/actions",
		"-H", "Content-Type: application/json",
		"-d", string(data),
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("fcAction %s failed: %w, output: %s", action, err, string(out))
	}
	return nil
}

// Execute runs a command inside the microVM via the guest agent.
func (s *microvmSandbox) Execute(ctx context.Context, cmd Command) (*Result, error) {
	s.beginRun()
	defer s.endRun()

	if s.agent == nil {
		if err := s.startVM(ctx); err != nil {
			return nil, err
		}
	}

	env := cmd.Env
	if s.proxy != nil {
		env = network.EnsureProxyEnv(env, "http://"+s.proxy.Addr())
	}

	req := &sandboxpb.ExecuteRequest{
		CommandId:  cmd.ID,
		Exec:       cmd.Exec,
		Args:       cmd.Args,
		Env:        env,
		WorkingDir: cmd.WorkingDir,
		Stdin:      cmd.Stdin,
		TimeoutMs:  cmd.Timeout.Milliseconds(),
	}

	start := time.Now()
	resp, err := s.agent.Execute(ctx, req)
	duration := time.Since(start)

	s.auditor.LogExecution(audit.ExecutionRecord{
		SandboxID: s.id,
		CommandID: cmd.ID,
		Exec:      cmd.Exec,
		Args:      cmd.Args,
		ExitCode:  int(resp.GetExitCode()),
		Success:   resp.GetSuccess(),
		ErrorMsg:  resp.GetError(),
		Duration:  duration,
		Timestamp: time.Now().UTC(),
	})

	if err != nil {
		return nil, fmt.Errorf("guest agent execute failed: %w", err)
	}

	var execErr error
	if resp.GetError() != "" {
		execErr = fmt.Errorf("%s", resp.GetError())
	}

	return &Result{
		CommandID:     cmd.ID,
		ExitCode:      int(resp.GetExitCode()),
		Success:       resp.GetSuccess(),
		Stdout:        resp.GetStdout(),
		Stderr:        resp.GetStderr(),
		Duration:      time.Duration(resp.GetDurationMs()) * time.Millisecond,
		SandboxID:     s.id,
		SecurityLevel: LevelIsolated,
		Metrics: &ExecutionMetrics{
			CPUMilliseconds: resp.GetDurationMs(),
		},
		Error: execErr,
	}, nil
}

// ExecuteStreaming runs a command and streams stdout/stderr/progress back.
func (s *microvmSandbox) ExecuteStreaming(
	ctx context.Context,
	cmd Command,
	onStdout func(data []byte),
	onStderr func(data []byte),
	onProgress func(progress float64),
) (*Result, error) {
	s.beginRun()
	defer s.endRun()

	if s.agent == nil {
		if err := s.startVM(ctx); err != nil {
			return nil, err
		}
	}

	env := cmd.Env
	if s.proxy != nil {
		env = network.EnsureProxyEnv(env, "http://"+s.proxy.Addr())
	}

	if len(cmd.Secrets) > 0 && s.secretProvider != nil {
		cleanup, injectedEnv, err := s.injectSecrets(ctx, cmd.Secrets, env)
		if err != nil {
			return nil, fmt.Errorf("secret injection failed: %w", err)
		}
		defer cleanup()
		env = injectedEnv
	}

	req := &sandboxpb.ExecuteRequest{
		CommandId:  cmd.ID,
		Exec:       cmd.Exec,
		Args:       cmd.Args,
		Env:        env,
		WorkingDir: cmd.WorkingDir,
		Stdin:      cmd.Stdin,
		TimeoutMs:  cmd.Timeout.Milliseconds(),
	}

	stream, err := s.agent.ExecuteStream(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("guest agent execute stream failed: %w", err)
	}

	var result *sandboxpb.ExecuteResponse
	for {
		chunk, err := stream.Recv()
		if err != nil {
			break
		}
		switch p := chunk.Payload.(type) {
		case *sandboxpb.StreamChunk_Stdout:
			if onStdout != nil {
				onStdout(p.Stdout)
			}
		case *sandboxpb.StreamChunk_Stderr:
			if onStderr != nil {
				onStderr(p.Stderr)
			}
		case *sandboxpb.StreamChunk_Progress:
			if onProgress != nil {
				onProgress(p.Progress)
			}
		case *sandboxpb.StreamChunk_Result:
			result = p.Result
		}
	}

	if result == nil {
		return nil, fmt.Errorf("stream ended without result")
	}

	var execErr error
	if result.GetError() != "" {
		execErr = fmt.Errorf("%s", result.GetError())
	}

	return &Result{
		CommandID:     cmd.ID,
		ExitCode:      int(result.GetExitCode()),
		Success:       result.GetSuccess(),
		Stdout:        result.GetStdout(),
		Stderr:        result.GetStderr(),
		Duration:      time.Duration(result.GetDurationMs()) * time.Millisecond,
		SandboxID:     s.id,
		SecurityLevel: LevelIsolated,
		Metrics: &ExecutionMetrics{
			CPUMilliseconds: result.GetDurationMs(),
		},
		Error: execErr,
	}, nil
}

// Cancel sends a cancel request to the guest agent.
func (s *microvmSandbox) Cancel(commandID string) error {
	if s.agent == nil {
		return fmt.Errorf("microVM not running")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_, err := s.agent.Cancel(ctx, &sandboxpb.CancelRequest{CommandId: commandID})
	return err
}

// Cleanup stops the microVM and removes workspace files.
func (s *microvmSandbox) Cleanup() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.agent != nil {
		_ = s.agent.close()
	}

	if s.vmPID > 0 {
		_ = s.fcAction(context.Background(), "SendCtrlAltDel")
		time.Sleep(500 * time.Millisecond)
		proc, _ := os.FindProcess(s.vmPID)
		if proc != nil {
			_ = proc.Kill()
		}
	}

	if s.proxy != nil {
		_ = s.proxy.Stop()
	}

	if err := os.RemoveAll(s.workspace); err != nil {
		return fmt.Errorf("failed to remove workspace: %w", err)
	}
	return nil
}

// Info returns sandbox metadata.
func (s *microvmSandbox) Info() SandboxInfo {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	return SandboxInfo{
		ID:           s.id,
		Level:        LevelIsolated,
		State:        s.state,
		WorkspaceDir: s.workspace,
		Persistent:   s.persistent,
		CreatedAt:    s.createdAt,
		ActiveTasks:  s.running,
	}
}

// Level returns the security level.
func (s *microvmSandbox) Level() SecurityLevel {
	return LevelIsolated
}

// Snapshot pauses the microVM and saves its full state to disk.
func (s *microvmSandbox) Snapshot(snapshotID string) error {
	snapshotDir := filepath.Join(s.workspace, "snapshots")
	if err := os.MkdirAll(snapshotDir, 0755); err != nil {
		return err
	}
	snapshotPath := filepath.Join(snapshotDir, snapshotID+".snap")
	memPath := filepath.Join(snapshotDir, snapshotID+".mem")

	payload := map[string]string{
		"snapshot_type": "Full",
		"snapshot_path": snapshotPath,
		"mem_file_path": memPath,
	}
	if err := s.fcPut(context.Background(), "/snapshot/create", payload); err != nil {
		return fmt.Errorf("failed to create snapshot: %w", err)
	}
	return nil
}

// Restore loads a previously saved snapshot and resumes the microVM.
func (s *microvmSandbox) Restore(snapshotID string) error {
	snapshotDir := filepath.Join(s.workspace, "snapshots")
	snapshotPath := filepath.Join(snapshotDir, snapshotID+".snap")
	memPath := filepath.Join(snapshotDir, snapshotID+".mem")

	payload := map[string]string{
		"snapshot_path": snapshotPath,
		"mem_file_path": memPath,
	}
	if err := s.fcPut(context.Background(), "/snapshot/load", payload); err != nil {
		return fmt.Errorf("failed to load snapshot: %w", err)
	}
	if err := s.fcAction(context.Background(), "ResumeInstance"); err != nil {
		return fmt.Errorf("failed to resume instance: %w", err)
	}
	return nil
}

// Filesystem returns a filesystem accessor backed by the guest agent.
func (s *microvmSandbox) Filesystem() Filesystem {
	return &microvmFilesystem{agent: s.agent, sandbox: s}
}

// PortForwarder returns a port forwarder backed by the guest agent.
func (s *microvmSandbox) PortForwarder() PortForwarder {
	return &microvmPortForwarder{agent: s.agent, sandbox: s}
}

func (s *microvmSandbox) beginRun() {
	s.mutex.Lock()
	s.running++
	s.state = "running"
	s.mutex.Unlock()
}

func (s *microvmSandbox) endRun() {
	s.mutex.Lock()
	if s.running > 0 {
		s.running--
	}
	if s.running == 0 {
		s.state = "idle"
	}
	s.mutex.Unlock()
}

func (s *microvmSandbox) injectSecrets(ctx context.Context, keys []string, env []string) (func(), []string, error) {
	secretsDir := "/dev/shm/.s2aa_secrets"
	if resp, err := s.agent.MkdirAll(ctx, secretsDir, 0700); err != nil {
		return nil, nil, err
	} else if !resp.GetSuccess() {
		return nil, nil, fmt.Errorf("%s", resp.GetError())
	}

	for _, key := range keys {
		value, err := s.secretProvider.GetSecret(ctx, key)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to resolve secret %s: %w", key, err)
		}
		resp, err := s.agent.WriteFile(ctx, filepath.Join(secretsDir, key), []byte(value), 0600)
		if err != nil {
			return nil, nil, err
		}
		if !resp.GetSuccess() {
			return nil, nil, fmt.Errorf("failed to write secret %s: %s", key, resp.GetError())
		}
	}

	// Inject metadata env vars
	env = append(env, "S2AA_SECRETS_DIR="+secretsDir)
	for _, key := range keys {
		env = append(env, key+"_FILE="+filepath.Join(secretsDir, key))
	}

	cleanup := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = s.agent.DeleteFile(ctx, secretsDir)
	}
	return cleanup, env, nil
}

func makeAllowFunc(caps *Capabilities) network.AllowFunc {
	if caps == nil {
		return func(string, int) bool { return true }
	}

	return func(host string, port int) bool {
		switch caps.NetworkAccess {
		case NetworkAllowAll:
			return true
		case NetworkBlockAll:
			return false
		case NetworkLocalOnly:
			return isLocalHost(host)
		case NetworkWhitelist:
			return matchWhitelist(caps, host, port)
		case NetworkBlacklist:
			return !matchBlacklist(caps, host, port)
		default:
			return true
		}
	}
}

func isLocalHost(host string) bool {
	ip := net.ParseIP(host)
	if ip != nil {
		return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()
	}
	return host == "localhost" || strings.HasSuffix(host, ".local")
}

func matchWhitelist(caps *Capabilities, host string, port int) bool {
	for _, d := range caps.AllowedDomains {
		if strings.HasSuffix(host, d) || host == d {
			return portAllowed(caps, port)
		}
	}
	for _, ipStr := range caps.AllowedIPs {
		_, cidr, err := net.ParseCIDR(ipStr)
		if err != nil {
			if ipStr == host {
				return portAllowed(caps, port)
			}
			continue
		}
		ip := net.ParseIP(host)
		if ip != nil && cidr.Contains(ip) {
			return portAllowed(caps, port)
		}
	}
	return false
}

func matchBlacklist(caps *Capabilities, host string, port int) bool {
	for _, d := range caps.BlockedDomains {
		if strings.HasSuffix(host, d) || host == d {
			return true
		}
	}
	return !portAllowed(caps, port)
}

func portAllowed(caps *Capabilities, port int) bool {
	if len(caps.AllowedPorts) == 0 {
		return true
	}
	for _, p := range caps.AllowedPorts {
		if p == port {
			return true
		}
	}
	return false
}

// microvmFilesystem implements Filesystem by delegating to the guest agent.
type microvmFilesystem struct {
	agent   *agentClient
	sandbox *microvmSandbox
}

func (fs *microvmFilesystem) ensureAgent() error {
	if fs.agent == nil {
		return fmt.Errorf("microVM agent not ready")
	}
	return nil
}

func (fs *microvmFilesystem) ReadFile(ctx context.Context, path string) ([]byte, error) {
	if err := fs.ensureAgent(); err != nil {
		return nil, err
	}
	resp, err := fs.agent.ReadFile(ctx, path)
	if err != nil {
		return nil, err
	}
	if !resp.GetSuccess() {
		return nil, fmt.Errorf("%s", resp.GetError())
	}
	return resp.GetData(), nil
}

func (fs *microvmFilesystem) WriteFile(ctx context.Context, path string, data []byte, perm os.FileMode) error {
	if err := fs.ensureAgent(); err != nil {
		return err
	}
	resp, err := fs.agent.WriteFile(ctx, path, data, uint32(perm))
	if err != nil {
		return err
	}
	if !resp.GetSuccess() {
		return fmt.Errorf("%s", resp.GetError())
	}
	return nil
}

func (fs *microvmFilesystem) ListFiles(ctx context.Context, path string) ([]FileInfo, error) {
	if err := fs.ensureAgent(); err != nil {
		return nil, err
	}
	resp, err := fs.agent.ListFiles(ctx, path)
	if err != nil {
		return nil, err
	}
	result := make([]FileInfo, 0, len(resp.GetEntries()))
	for _, e := range resp.GetEntries() {
		result = append(result, FileInfo{
			Name:    e.GetName(),
			Path:    e.GetPath(),
			Size:    e.GetSize(),
			Mode:    os.FileMode(e.GetMode()),
			ModTime: time.Unix(e.GetModTimeUnix(), 0),
			IsDir:   e.GetIsDir(),
		})
	}
	return result, nil
}

func (fs *microvmFilesystem) DeleteFile(ctx context.Context, path string) error {
	if err := fs.ensureAgent(); err != nil {
		return err
	}
	resp, err := fs.agent.DeleteFile(ctx, path)
	if err != nil {
		return err
	}
	if !resp.GetSuccess() {
		return fmt.Errorf("%s", resp.GetError())
	}
	return nil
}

func (fs *microvmFilesystem) MkdirAll(ctx context.Context, path string, perm os.FileMode) error {
	if err := fs.ensureAgent(); err != nil {
		return err
	}
	resp, err := fs.agent.MkdirAll(ctx, path, uint32(perm))
	if err != nil {
		return err
	}
	if !resp.GetSuccess() {
		return fmt.Errorf("%s", resp.GetError())
	}
	return nil
}

func (fs *microvmFilesystem) Stat(ctx context.Context, path string) (*FileInfo, error) {
	if err := fs.ensureAgent(); err != nil {
		return nil, err
	}
	resp, err := fs.agent.Stat(ctx, path)
	if err != nil {
		return nil, err
	}
	if !resp.GetSuccess() {
		return nil, fmt.Errorf("%s", resp.GetError())
	}
	info := resp.GetInfo()
	return &FileInfo{
		Name:    info.GetName(),
		Path:    info.GetPath(),
		Size:    info.GetSize(),
		Mode:    os.FileMode(info.GetMode()),
		ModTime: time.Unix(info.GetModTimeUnix(), 0),
		IsDir:   info.GetIsDir(),
	}, nil
}

func (fs *microvmFilesystem) UploadFile(ctx context.Context, hostPath, sandboxPath string) error {
	data, err := os.ReadFile(hostPath)
	if err != nil {
		return err
	}
	return fs.WriteFile(ctx, sandboxPath, data, 0644)
}

func (fs *microvmFilesystem) DownloadFile(ctx context.Context, sandboxPath, hostPath string) error {
	data, err := fs.ReadFile(ctx, sandboxPath)
	if err != nil {
		return err
	}
	return os.WriteFile(hostPath, data, 0644)
}

// microvmPortForwarder implements PortForwarder for microVMs.
type microvmPortForwarder struct {
	agent   *agentClient
	sandbox *microvmSandbox
}

func (pf *microvmPortForwarder) ExposePort(ctx context.Context, containerPort int) (string, func(), error) {
	if pf.agent == nil {
		return "", nil, fmt.Errorf("microVM agent not ready")
	}
	resp, err := pf.agent.ExposePort(ctx, int32(containerPort))
	if err != nil {
		return "", nil, err
	}
	url := fmt.Sprintf("http://vsock-%d:%d", pf.sandbox.guestCID, containerPort)
	if resp.GetPublicUrl() != "" {
		url = resp.GetPublicUrl()
	}
	return url, func() {}, nil
}

func (pf *microvmPortForwarder) ListExposedPorts() []PortMapping {
	return nil
}
