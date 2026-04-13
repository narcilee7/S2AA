package sandbox

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/narcilee7/S2AA/internal/utils"
)

// isolatedSandbox provides container-isolated execution.
type isolatedSandbox struct {
	id          string
	limits      *ResourceLimits
	caps        *Capabilities
	baseDir     string
	runtime     string // docker, podman, runc
	image       string // Container image to use
	tempDir     string
	containerID string
	mutex       sync.RWMutex
	state       string
	createdAt   time.Time
}

// ContainerRuntime defines supported container runtimesories.
type ContainerRuntime string

const (
	RuntimeDocker ContainerRuntime = "docker"
	RuntimePodman ContainerRuntime = "podman"
	RuntimeRunc   ContainerRuntime = "runc"
	RuntimeAuto   ContainerRuntime = "auto"
)

// DefaultImage returns default container image for execution.
func DefaultImage(runtime ContainerRuntime) string {
	switch runtime {
	case RuntimeDocker:
		return "metis-runner:latest"
	case RuntimePodman:
		return "docker.io/metsy/metysetis-runner:latest"
	case RuntimeRunc:
		return "" // runc uses rootfs directly
	default:
		return "metis-runner:latest"
	}
}

// newIsolatedSandbox creates a new L3 isolated sandbox.
func newIsolatedSandbox(
	limits *ResourceLimits,
	caps *Capabilities,
	baseDir string,
	runtime string,
) (*isolatedSandbox, error) {
	if limits == nil {
		limits = DefaultResourceLimits(LevelIsolated)
	}
	if caps == nil {
		caps = DefaultCapabilities(LevelIsolated)
	}
	if runtime == "" {
		runtime = string(RuntimeAuto)
	}

	// Detect runtime if auto
	containerRuntime := ContainerRuntime(runtime)
	if containerRuntime == RuntimeAuto {
		detected, err := detectContainerRuntime()
		if err != nil {
			// Fall back to docker if detection fails
			containerRuntime = RuntimeDocker
		} else {
			containerRuntime = detected
		}
		runtime = string(containerRuntime)
	}

	sandbox := &isolatedSandbox{
		id:        utils.GenerateID(),
		limits:    limits,
		caps:      caps,
		baseDir:   baseDir,
		runtime:   runtime,
		image:     DefaultImage(containerRuntime),
		tempDir:   filepath.Join(baseDir, ".containers", utils.GenerateID()),
		state:     "idle",
		createdAt: time.Now().UTC(),
	}

	// Create temp directory
	if err := os.MkdirAll(sandbox.tempDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create temp directory: %w", err)
	}

	return sandbox, nil
}

// detectContainerRuntime detects available container runtime.
func detectContainerRuntime() (ContainerRuntime, error) {
	// Check for Docker
	if _, err := exec.LookPath("docker"); err == nil {
		// Verify docker is running
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "docker", "ps")
		if err := cmd.Run(); err == nil {
			return RuntimeDocker, nil
		}
	}

	// Check for Podman
	if _, err := exec.LookPath("podman"); err == nil {
		return RuntimePodman, nil
	}

	// Check for runc
	if _, err := exec.LookPath("runc"); err == nil {
		return RuntimeRunc, nil
	}

	return "", fmt.Errorf("no container runtime found (docker, podman, or runc)")
}

// checkContainerRuntime verifies the container runtime is available.
func (s *isolatedSandbox) checkContainerRuntime() error {
	if _, err := exec.LookPath(s.runtime); err != nil {
		return fmt.Errorf("container runtime '%s' not found: %w", s.runtime, err)
	}
	return nil
}

// Execute executes a command in an isolated container.
func (s *isolatedSandbox) Execute(ctx context.Context, cmd Command) (*Result, error) {
	s.mutex.Lock()
	s.state = "running"
	s.mutex.Unlock()
	defer func() {
		s.mutex.Lock()
		s.state = "idle"
		s.mutex.Unlock()
	}()

	// Verify container runtime
	if err := s.checkContainerRuntime(); err != nil {
		return nil, fmt.Errorf("container runtime check failed: %w", err)
	}

	// Validate command security
	if err := s.checkCommandSecurity(cmd); err != nil {
		return nil, fmt.Errorf("command security check failed: %w", err)
	}

	// Execute based on runtime
	switch ContainerRuntime(s.runtime) {
	case RuntimeDocker:
		return s.executeDocker(ctx, cmd)
	case RuntimePodman:
		return s.executePodman(ctx, cmd)
	case RuntimeRunc:
		return s.executeRunc(ctx, cmd)
	default:
		return nil, fmt.Errorf("unsupported container runtime: %s", s.runtime)
	}
}

// executeDocker executes command using Docker.
func (s *isolatedSandbox) executeDocker(ctx context.Context, cmd Command) (*Result, error) {
	// Prepare container config
	config := s.prepareDockerConfig(cmd)
	_, err := json.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal container config: %w", err)
	}

	// Create container
	args := []string{"create", "--name", s.id}
	if s.image != "" {
		args = append(args, s.image)
	} else {
		// Use scratch image if no image specified
		args = append(args, "scratch")
	}

	createCmd := exec.CommandContext(ctx, "docker", args...)
	createOutput, err := createCmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to create container: %w, output: %s", err, string(createOutput))
	}

	s.containerID = string(createOutput)

	// Start container
	startCmd := exec.CommandContext(ctx, "docker", "start", s.containerID)
	if err := startCmd.Run(); err != nil {
		s.cleanupContainer()
		return nil, fmt.Errorf("failed to start container: %w", err)
	}

	// Execute command
	execArgs := []string{"exec", s.containerID}
	if len(cmd.Args) > 0 {
		execArgs = append(execArgs, cmd.Exec)
		execArgs = append(execArgs, cmd.Args...)
	} else {
		execArgs = append(execArgs, cmd.Exec)
	}

	execCmd := exec.CommandContext(ctx, "docker", execArgs...)
	stdoutPipe, err := execCmd.StdoutPipe()
	if err != nil {
		s.cleanupContainer()
		return nil, fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	stderrPipe, err := execCmd.StderrPipe()
	if err != nil {
		s.cleanupContainer()
		return nil, fmt.Errorf("failed to create stderr pipe: %w", err)
	}

	startTime := time.Now()
	if err := execCmd.Start(); err != nil {
		s.cleanupContainer()
		return nil, fmt.Errorf("failed to execute command in container: %w", err)
	}

	// Read outputs
	var stdoutBuf, stderrBuf []byte
	done := make(chan bool, 2)

	go func() {
		defer close(done)
		stdoutBuf, _ = readAll(stdoutPipe)
	}()

	go func() {
		defer close(done)
		stderrBuf, _ = readAll(stderrPipe)
	}()

	// Wait for command completion
	execErr := execCmd.Wait()
	duration := time.Since(startTime)

	// Wait for output readers
	<-done
	<-done

	// Cleanup container
	_ = s.cleanupContainer()

	// Prepare result
	exitCode := 0
	success := true
	if execErr != nil {
		if exitErr, ok := execErr.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		}
		success = false
	}

	return &Result{
		CommandID:     cmd.ID,
		ExitCode:      exitCode,
		Success:       success,
		Error:         execErr,
		Stdout:        stdoutBuf,
		Stderr:        stderrBuf,
		Duration:      duration,
		SandboxID:     s.id,
		SecurityLevel: LevelIsolated,
		Metrics: &ExecutionMetrics{
			CPUMilliseconds: duration.Milliseconds(),
			ContainerID:     s.containerID,
			ImageName:       s.image,
		},
	}, nil
}

// executePodman executes command using Podman.
func (s *isolatedSandbox) executePodman(ctx context.Context, cmd Command) (*Result, error) {
	// Podman is compatible with Docker CLI for most operations
	// For simplicity, reuse docker execution with 'podman' as runtime
	s.runtime = "docker" // Temporarily switch for execution
	defer func() { s.runtime = "podman" }()

	// Use podman command
	// Note: This is a simplified implementation
	return nil, fmt.Errorf("podman execution not fully implemented yet")
}

// executeRunc executes command using runc.
func (s *isolatedSandbox) executeRunc(ctx context.Context, cmd Command) (*Result, error) {
	return nil, fmt.Errorf("runc execution not implemented yet")
}

// prepareDockerConfig prepares Docker container configuration.
func (s *isolatedSandbox) prepareDockerConfig(cmd Command) map[string]interface{} {
	config := map[string]interface{}{
		"HostConfig": map[string]interface{}{
			"Memory":      s.limits.MemoryBytes,
			"CpuShares":   512, // Default CPU shares
			"AutoRemove":  true,
			"NetworkMode": "none", // No network by default
		},
		"Image": s.image,
	}

	// Configure network if allowed
	if s.caps != nil && s.caps.NetworkAccess == NetworkAllowAll {
		config["HostConfig"].(map[string]interface{})["NetworkMode"] = "bridge"
	} else if s.caps != nil && s.caps.NetworkAccess == NetworkLocalOnly {
		config["HostConfig"].(map[string]interface{})["NetworkMode"] = "host"
	}

	// Configure working directory
	if cmd.WorkingDir != "" {
		config["WorkingDir"] = cmd.WorkingDir
	}

	return config
}

// checkCommandSecurity checks if a command is allowed to execute.
func (s *isolatedSandbox) checkCommandSecurity(cmd Command) error {
	if s.caps == nil {
		return nil
	}

	// Check blocked executables
	for _, blocked := range s.caps.BlockedExecs {
		if cmd.Exec == blocked {
			return fmt.Errorf("command is blocked: %s", cmd.Exec)
		}
	}

	// Check allowed executables (whitelist mode)
	if len(s.caps.AllowedExecs) > 0 {
		allowed := false
		for _, allowedExec := range s.caps.AllowedExecs {
			if cmd.Exec == allowedExec {
				allowed = true
				break
			}
		}
		if !allowed {
			return fmt.Errorf("command not in allowed list: %s", cmd.Exec)
		}
	}

	return nil
}

// cleanupContainer removes the container.
func (s *isolatedSandbox) cleanupContainer() error {
	if s.containerID == "" {
		return nil
	}

	// Stop and remove container
	rmCmd := exec.Command("docker", "rm", "-f", s.containerID)
	_ = rmCmd.Run()

	s.containerID = ""
	return nil
}

// ExecuteStreaming executes a command with streaming output.
func (s *isolatedSandbox) ExecuteStreaming(
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

	// Verify container runtime
	if err := s.checkContainerRuntime(); err != nil {
		return nil, fmt.Errorf("container runtime check failed: %w", err)
	}

	// Validate command security
	if err := s.checkCommandSecurity(cmd); err != nil {
		return nil, fmt.Errorf("command security check failed: %w", err)
	}

	// Execute based on runtime
	switch ContainerRuntime(s.runtime) {
	case RuntimeDocker:
		return s.executeDockerStreaming(ctx, cmd, onStdout, onStderr, onProgress)
	case RuntimePodman:
		// Podman compatible with Docker for streaming
		s.runtime = "docker"
		defer func() { s.runtime = "podman" }()
		return s.executeDockerStreaming(ctx, cmd, onStdout, onStderr, onProgress)
	case RuntimeRunc:
		// runc doesn't support streaming easily, fall back to Execute
		result, err := s.executeRunc(ctx, cmd)
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
	default:
		return nil, fmt.Errorf("unsupported container runtime: %s", s.runtime)
	}
}

// executeDockerStreaming executes command using Docker with streaming output.
func (s *isolatedSandbox) executeDockerStreaming(
	ctx context.Context,
	cmd Command,
	onStdout func(data []byte),
	onStderr func(data []byte),
	onProgress func(progress float64),
) (*Result, error) {
	// Prepare container config
	config := s.prepareDockerConfig(cmd)
	_, err := json.Marshal(config)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal container config: %w", err)
	}

	// Create container
	args := []string{"create", "--name", s.id}
	if s.image != "" {
		args = append(args, s.image)
	} else {
		args = append(args, "scratch")
	}

	createCmd := exec.CommandContext(ctx, "docker", args...)
	createOutput, err := createCmd.CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to create container: %w, output: %s", err, string(createOutput))
	}

	s.containerID = string(createOutput)

	// Start container
	startCmd := exec.CommandContext(ctx, "docker", "start", s.containerID)
	if err := startCmd.Run(); err != nil {
		s.cleanupContainer()
		return nil, fmt.Errorf("failed to start container: %w", err)
	}

	// Execute command with streaming
	execArgs := []string{"exec", s.containerID}
	if len(cmd.Args) > 0 {
		execArgs = append(execArgs, cmd.Exec)
		execArgs = append(execArgs, cmd.Args...)
	} else {
		execArgs = append(execArgs, cmd.Exec)
	}

	execCmd := exec.CommandContext(ctx, "docker", execArgs...)

	stdoutPipe, err := execCmd.StdoutPipe()
	if err != nil {
		s.cleanupContainer()
		return nil, fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	stderrPipe, err := execCmd.StderrPipe()
	if err != nil {
		stdoutPipe.Close()
		s.cleanupContainer()
		return nil, fmt.Errorf("failed to create stderr pipe: %w", err)
	}

	startTime := time.Now()
	if err := execCmd.Start(); err != nil {
		stdoutPipe.Close()
		stderrPipe.Close()
		s.cleanupContainer()
		return nil, fmt.Errorf("failed to execute command in container: %w", err)
	}

	// Stream outputs
	done := make(chan bool, 2)
	var stdoutBuf, stderrBuf []byte

	// Stream stdout
	go func() {
		defer close(done)
		defer stdoutPipe.Close()
		buf := make([]byte, 4096)
		for {
			n, err := stdoutPipe.Read(buf)
			if n > 0 {
				data := make([]byte, n)
				copy(data, buf[:n])
				stdoutBuf = append(stdoutBuf, data...)
				if onStdout != nil {
					onStdout(data)
				}
			}
			if err != nil {
				break
			}
		}
	}()

	// Stream stderr
	go func() {
		defer close(done)
		defer stderrPipe.Close()
		buf := make([]byte, 4096)
		for {
			n, err := stderrPipe.Read(buf)
			if n > 0 {
				data := make([]byte, n)
				copy(data, buf[:n])
				stderrBuf = append(stderrBuf, data...)
				if onStderr != nil {
					onStderr(data)
				}
			}
			if err != nil {
				break
			}
		}
	}()

	// Progress updates if timeout specified
	if onProgress != nil && cmd.Timeout > 0 {
		progressTicker := time.NewTicker(100 * time.Millisecond)
		go func() {
			for {
				select {
				case <-progressTicker.C:
					elapsed := time.Since(startTime).Seconds()
					progress := elapsed / cmd.Timeout.Seconds()
					if progress > 1.0 {
						progress = 1.0
					}
					onProgress(progress)
				case <-ctx.Done():
					progressTicker.Stop()
					return
				case <-done:
					progressTicker.Stop()
					return
				}
			}
		}()
	}

	// Wait for command completion
	execErr := execCmd.Wait()
	duration := time.Since(startTime)

	// Wait for output streams
	<-done
	<-done

	// Cleanup container
	_ = s.cleanupContainer()

	// Prepare result
	exitCode := 0
	success := true
	if execErr != nil {
		if exitErr, ok := execErr.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		}
		success = false
	}

	return &Result{
		CommandID:     cmd.ID,
		ExitCode:      exitCode,
		Success:       success,
		Error:         execErr,
		Stdout:        stdoutBuf,
		Stderr:        stderrBuf,
		Duration:      duration,
		SandboxID:     s.id,
		SecurityLevel: LevelIsolated,
		Metrics: &ExecutionMetrics{
			CPUMilliseconds: duration.Milliseconds(),
			ContainerID:     s.containerID,
			ImageName:       s.image,
		},
	}, nil
}

// Cancel cancels a running command.
func (s *isolatedSandbox) Cancel(commandID string) error {
	// Stop the container
	if s.containerID != "" {
		stopCmd := exec.Command("docker", "stop", s.containerID)
		if err := stopCmd.Run(); err != nil {
			return fmt.Errorf("failed to stop container: %w", err)
		}
		return nil
	}
	return fmt.Errorf("no running container to cancel")
}

// Cleanup cleans up sandbox resources.
func (s *isolatedSandbox) Cleanup() error {
	// Clean up container
	if err := s.cleanupContainer(); err != nil {
		return err
	}

	// Clean up temp directory
	if err := os.RemoveAll(s.tempDir); err != nil {
		return err
	}

	return nil
}

// Info returns sandbox information.
func (s *isolatedSandbox) Info() SandboxInfo {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	return SandboxInfo{
		ID:          s.id,
		Level:       LevelIsolated,
		State:       s.state,
		CreatedAt:   s.createdAt,
		ActiveTasks: 0,
	}
}

// Level returns security level.
func (s *isolatedSandbox) Level() SecurityLevel {
	return LevelIsolated
}

// Filesystem returns a legacy host filesystem accessor.
func (s *isolatedSandbox) Filesystem() Filesystem {
	return newLegacyFilesystem(s.tempDir)
}

// PortForwarder returns a no-op port forwarder.
func (s *isolatedSandbox) PortForwarder() PortForwarder {
	return defaultNoopPortForwarder
}

// Snapshot is not supported for legacy isolated sandbox.
func (s *isolatedSandbox) Snapshot(snapshotID string) error {
	return fmt.Errorf("snapshot not supported for isolated sandbox")
}

// Restore is not supported for legacy isolated sandbox.
func (s *isolatedSandbox) Restore(snapshotID string) error {
	return fmt.Errorf("restore not supported for isolated sandbox")
}

// Runtime returns container runtime being used.
func (s *isolatedSandbox) Runtime() string {
	return s.runtime
}

// Image returns container image being used.
func (s *isolatedSandbox) Image() string {
	return s.image
}

// ContainerID returns current container ID.
func (s *isolatedSandbox) ContainerID() string {
	return s.containerID
}
