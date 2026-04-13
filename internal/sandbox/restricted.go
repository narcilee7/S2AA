package sandbox

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"github.com/narcilee7/agent-sandbox/internal/utils"
	"golang.org/x/sys/unix"
)

// restrictedSandbox provides process-level restricted execution.
type restrictedSandbox struct {
	id        string
	limits    *ResourceLimits
	caps      *Capabilities
	tempDir   string
	baseDir   string
	mutex     sync.RWMutex
	state     string
	running   int
	createdAt time.Time

	// cgroup v2 support
	cgroupPath  string
	cgroupSetup bool
}

// newRestrictedSandbox creates a new L2 restricted sandbox.
func newRestrictedSandbox(
	limits *ResourceLimits,
	caps *Capabilities,
	tempDir string,
	baseDir string,
	enableCgroup bool,
) (*restrictedSandbox, error) {
	if limits == nil {
		limits = DefaultResourceLimits(LevelRestricted)
	}
	if caps == nil {
		caps = DefaultCapabilities(LevelRestricted)
	}

	sandbox := &restrictedSandbox{
		id:          utils.GenerateID(),
		limits:      limits,
		caps:        caps,
		tempDir:     tempDir,
		baseDir:     baseDir,
		state:       "idle",
		createdAt:   time.Now().UTC(),
		cgroupSetup: false,
	}

	if enableCgroup {
		if err := sandbox.setupCgroup(); err != nil {
			// Log warning but don't fail - sandbox will work without cgroup
			// cgroup requires root privileges which may not be available
			sandbox.cgroupPath = ""
			sandbox.cgroupSetup = false
		} else {
			sandbox.cgroupSetup = true
		}
	}

	// Create temp directory if needed
	if err := os.MkdirAll(tempDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create temp directory: %w", err)
	}

	return sandbox, nil
}

// setupCgroup sets up cgroup v2 for resource limiting.
// Requires root privileges on most systems.
func (s *restrictedSandbox) setupCgroup() error {
	// Check if cgroup v2 is available
	cgroupRoot := "/sys/fs/cgroup"
	if _, err := os.Stat(cgroupRoot); err != nil {
		return fmt.Errorf("cgroup v2 not available: %w", err)
	}

	// Create a cgroup for this sandbox
	s.cgroupPath = filepath.Join(cgroupRoot, "metis", s.id)
	if err := os.MkdirAll(s.cgroupPath, 0755); err != nil {
		return fmt.Errorf("failed to create cgroup: %w", err)
	}

	// Set CPU limits if configured
	if s.limits.CPUMax > 0 && s.limits.CPUPercent > 0 {
		cpuMaxPath := filepath.Join(s.cgroupPath, "cpu.max")
		cpuMax := fmt.Sprintf("%d 100000", int(s.limits.CPUMax*100000))
		if err := os.WriteFile(cpuMaxPath, []byte(cpuMax), 0644); err != nil {
			// Non-fatal: write may fail if file doesn't exist
		}
	}

	// Set memory limits if configured
	if s.limits.MemoryBytes > 0 {
		memoryMaxPath := filepath.Join(s.cgroupPath, "memory.max")
		memoryMax := fmt.Sprintf("%d", s.limits.MemoryBytes)
		if err := os.WriteFile(memoryMaxPath, []byte(memoryMax), 0644); err != nil {
			// Non-fatal: write may fail if memory controller not enabled
		}

		// Set memory swap limit
		if s.limits.MemorySwap > 0 {
			memorySwapPath := filepath.Join(s.cgroupPath, "memory.swap.max")
			memorySwap := fmt.Sprintf("%d", s.limits.MemorySwap)
			if err := os.WriteFile(memorySwapPath, []byte(memorySwap), 0644); err != nil {
				// Non-fatal
			}
		}
	}

	// Set pids limit if configured
	if s.limits.MaxProcesses > 0 {
		pidsMaxPath := filepath.Join(s.cgroupPath, "pids.max")
		pidsMax := fmt.Sprintf("%d", s.limits.MaxProcesses)
		if err := os.WriteFile(pidsMaxPath, []byte(pidsMax), 0644); err != nil {
			// Non-fatal
		}
	}

	return nil
}

// addProcessToCgroup adds a process to sandbox cgroup.
func (s *restrictedSandbox) addProcessToCgroup(pid int) error {
	if !s.cgroupSetup || s.cgroupPath == "" {
		return nil
	}

	cgroupProcsPath := filepath.Join(s.cgroupPath, "cgroup.procs")
	procData := fmt.Sprintf("%d", pid)
	return os.WriteFile(cgroupProcsPath, []byte(procData), 0644)
}

// cleanupCgroup removes sandbox cgroup.
func (s *restrictedSandbox) cleanupCgroup() error {
	if !s.cgroupSetup || s.cgroupPath == "" {
		return nil
	}

	// First, kill all processes in cgroup
	cgroupKillPath := filepath.Join(s.cgroupPath, "cgroup.kill")
	if _, err := os.Stat(cgroupKillPath); err == nil {
		os.WriteFile(cgroupKillPath, []byte("1"), 0644)
	}

	// Then remove directory
	return os.RemoveAll(s.cgroupPath)
}

// checkCommandSecurity checks if a command is allowed to execute.
func (s *restrictedSandbox) checkCommandSecurity(cmd Command) error {
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

	// Check working directory against allowed paths
	if cmd.WorkingDir != "" {
		if err := s.checkPathAccess(cmd.WorkingDir, s.caps.ReadPaths); err != nil {
			return fmt.Errorf("working directory access denied: %w", err)
		}
	}

	return nil
}

// checkPathAccess checks if a path is accessible based on allowed paths.
func (s *restrictedSandbox) checkPathAccess(path string, allowedPaths []string) error {
	absPath, err := filepath.Abs(path)
	if err != nil {
		return err
	}

	if len(allowedPaths) == 0 {
		return nil // No restrictions
	}

	for _, pattern := range allowedPaths {
		matched, err := filepath.Match(pattern, absPath)
		if err != nil {
			continue
		}
		if matched {
			return nil
		}
	}

	return fmt.Errorf("path not allowed: %s", absPath)
}

// applyResourceLimits applies resource limits to process.
func (s *restrictedSandbox) applyResourceLimits() error {
	if s.limits == nil {
		return nil
	}

	// Set resource limits
	var rlimit unix.Rlimit

	// Limit file descriptors
	if s.limits.MaxFiles > 0 {
		rlimit.Cur = uint64(s.limits.MaxFiles)
		rlimit.Max = uint64(s.limits.MaxFiles)
		if err := unix.Setrlimit(unix.RLIMIT_NOFILE, &rlimit); err != nil {
			return fmt.Errorf("failed to set file descriptor limit: %w", err)
		}
	}

	// Limit CPU time
	if s.limits.Timeout > 0 {
		cpuSec := int64(s.limits.Timeout.Seconds())
		rlimit.Cur = uint64(cpuSec)
		rlimit.Max = uint64(cpuSec)
		if err := unix.Setrlimit(unix.RLIMIT_CPU, &rlimit); err != nil {
			return fmt.Errorf("failed to set CPU time limit: %w", err)
		}
	}

	return nil
}

// Execute executes a command with restrictions.
func (s *restrictedSandbox) Execute(ctx context.Context, cmd Command) (*Result, error) {
	s.beginRun()
	defer s.endRun()

	// Validate command security
	if err := s.checkCommandSecurity(cmd); err != nil {
		return nil, fmt.Errorf("command security check failed: %w", err)
	}

	// Prepare command execution
	execCmd := exec.CommandContext(ctx, cmd.Exec, cmd.Args...)

	// Set working directory
	if cmd.WorkingDir == "" {
		execCmd.Dir = s.tempDir
	} else {
		execCmd.Dir = cmd.WorkingDir
	}

	// Set environment variables
	if len(cmd.Env) > 0 {
		execCmd.Env = cmd.Env
	} else {
		execCmd.Env = os.Environ()
	}

	// Filter environment variables based on capabilities
	if len(s.caps.AllowedEnv) > 0 {
		filteredEnv := make([]string, 0)
		for _, env := range execCmd.Env {
			envName := ""
			for i, c := range env {
				if c == '=' {
					envName = env[:i]
					break
				}
			}
			for _, allowed := range s.caps.AllowedEnv {
				if envName == allowed {
					filteredEnv = append(filteredEnv, env)
					break
				}
			}
		}
		execCmd.Env = filteredEnv
	}

	// Setup pipes for I/O
	stdinPipe, err := execCmd.StdinPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdin pipe: %w", err)
	}

	stdoutPipe, err := execCmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	stderrPipe, err := execCmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stderr pipe: %w", err)
	}

	// Set process group for better control (cross-platform)
	execCmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}

	// Start of command
	startTime := time.Now()
	if err := execCmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start command: %w", err)
	}

	// Add process to cgroup if setup
	if err := s.addProcessToCgroup(execCmd.Process.Pid); err != nil {
		// Non-fatal: process will still run without cgroup
	}

	// Apply resource limits
	_ = s.applyResourceLimits()

	// Write stdin if provided
	if len(cmd.Stdin) > 0 {
		go func() {
			defer stdinPipe.Close()
			stdinPipe.Write(cmd.Stdin)
		}()
	} else {
		stdinPipe.Close()
	}

	// Wait for completion with timeout
	resultChan := make(chan error, 1)
	go func() {
		resultChan <- execCmd.Wait()
	}()

	// Read outputs
	done := make(chan bool)
	var stdoutBuf, stderrBuf []byte
	go func() {
		stdoutBuf, _ = readAll(stdoutPipe)
		done <- true
	}()
	go func() {
		stderrBuf, _ = readAll(stderrPipe)
		done <- true
	}()

	// Wait for command completion or context cancellation
	var execErr error
	select {
	case execErr = <-resultChan:
		// Command completed
	case <-ctx.Done():
		// Context cancelled, kill process
		execCmd.Process.Kill()
		execErr = ctx.Err()
	}

	// Wait for output readers to finish
	<-done
	<-done

	duration := time.Since(startTime)

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
		SecurityLevel: LevelRestricted,
		Metrics: &ExecutionMetrics{
			CPUMilliseconds: duration.Milliseconds(),
		},
	}, nil
}

// ExecuteStreaming executes a command with streaming output.
func (s *restrictedSandbox) ExecuteStreaming(
	ctx context.Context,
	cmd Command,
	onStdout func(data []byte),
	onStderr func(data []byte),
	onProgress func(progress float64),
) (*Result, error) {
	s.beginRun()
	defer s.endRun()

	// Validate command security
	if err := s.checkCommandSecurity(cmd); err != nil {
		return nil, fmt.Errorf("command security check failed: %w", err)
	}

	// Prepare command execution
	execCmd := exec.CommandContext(ctx, cmd.Exec, cmd.Args...)

	if cmd.WorkingDir == "" {
		execCmd.Dir = s.tempDir
	} else {
		execCmd.Dir = cmd.WorkingDir
	}

	if len(cmd.Env) > 0 {
		execCmd.Env = cmd.Env
	} else {
		execCmd.Env = os.Environ()
	}

	// Set process group (cross-platform)
	execCmd.SysProcAttr = &syscall.SysProcAttr{
		Setpgid: true,
	}

	// Setup pipes
	stdoutPipe, err := execCmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	stderrPipe, err := execCmd.StderrPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stderr pipe: %w", err)
	}

	// Start of command
	startTime := time.Now()
	if err := execCmd.Start(); err != nil {
		return nil, fmt.Errorf("failed to start command: %w", err)
	}

	// Add to cgroup
	_ = s.addProcessToCgroup(execCmd.Process.Pid)
	_ = s.applyResourceLimits()

	// Stream outputs
	var stdoutBuf, stderrBuf []byte
	done := make(chan bool, 2)

	// Stream stdout
	go func() {
		defer close(done)
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

	// Wait for command
	waitChan := make(chan error, 1)
	go func() {
		waitChan <- execCmd.Wait()
	}()

	// Report progress periodically
	if onProgress != nil && cmd.Timeout > 0 {
		progressTicker := time.NewTicker(100 * time.Millisecond)
		defer progressTicker.Stop()
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
					return
				case <-waitChan:
					return
				}
			}
		}()
	}

	// Wait for completion
	execErr := <-waitChan
	duration := time.Since(startTime)

	// Wait for output streams
	<-done
	<-done

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
		SecurityLevel: LevelRestricted,
		Metrics: &ExecutionMetrics{
			CPUMilliseconds: duration.Milliseconds(),
		},
	}, nil
}

// Cancel cancels a running command.
func (s *restrictedSandbox) Cancel(commandID string) error {
	// For L2, we kill the process group via cgroup
	if s.cgroupSetup && s.cgroupPath != "" {
		// Kill all processes in cgroup
		cgroupKillPath := filepath.Join(s.cgroupPath, "cgroup.kill")
		if _, err := os.Stat(cgroupKillPath); err == nil {
			return os.WriteFile(cgroupKillPath, []byte("1"), 0644)
		}
	}
	return fmt.Errorf("no running command to cancel")
}

// Cleanup cleans up sandbox resources.
func (s *restrictedSandbox) Cleanup() error {
	// Clean up cgroup
	if err := s.cleanupCgroup(); err != nil {
		return err
	}

	// Clean up temp directory
	if err := os.RemoveAll(s.tempDir); err != nil {
		return err
	}

	return nil
}

// Info returns sandbox information.
func (s *restrictedSandbox) Info() SandboxInfo {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	return SandboxInfo{
		ID:          s.id,
		Level:       LevelRestricted,
		State:       s.state,
		CreatedAt:   s.createdAt,
		ActiveTasks: s.running,
	}
}

// Level returns security level.
func (s *restrictedSandbox) Level() SecurityLevel {
	return LevelRestricted
}

// Filesystem returns a legacy host filesystem accessor.
func (s *restrictedSandbox) Filesystem() Filesystem {
	return newLegacyFilesystem(s.tempDir)
}

// PortForwarder returns a no-op port forwarder.
func (s *restrictedSandbox) PortForwarder() PortForwarder {
	return defaultNoopPortForwarder
}

// readAll reads all data from a reader.
func readAll(r io.ReadCloser) ([]byte, error) {
	defer r.Close()
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)

	for {
		n, err := r.Read(tmp)
		if n > 0 {
			buf = append(buf, tmp[:n]...)
		}
		if err != nil {
			break
		}
	}

	return buf, nil
}

func (s *restrictedSandbox) beginRun() {
	s.mutex.Lock()
	s.running++
	s.state = "running"
	s.mutex.Unlock()
}

func (s *restrictedSandbox) endRun() {
	s.mutex.Lock()
	if s.running > 0 {
		s.running--
	}
	if s.running == 0 {
		s.state = "idle"
	}
	s.mutex.Unlock()
}
