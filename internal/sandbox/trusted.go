package sandbox

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"sync"
	"time"

	"github.com/narcilee7/agent-sandbox/internal/utils"
)

// trustedSandbox provides unrestricted command execution.
type trustedSandbox struct {
	id        string
	limits    *ResourceLimits
	caps      *Capabilities
	tempDir   string
	processes map[string]*processInfo
	mutex     sync.RWMutex
	state     string
	running   int
	createdAt time.Time
}

// processInfo tracks a running process.
type processInfo struct {
	started time.Time
	ctx     context.Context
	cancel  context.CancelFunc
}

// newTrustedSandbox creates a new L1 trusted sandbox.
func newTrustedSandbox(
	limits *ResourceLimits,
	caps *Capabilities,
	tempDir string,
) (*trustedSandbox, error) {
	return &trustedSandbox{
		id:        utils.GenerateID(),
		limits:    limits,
		caps:      caps,
		tempDir:   tempDir,
		processes: make(map[string]*processInfo),
		state:     "idle",
		createdAt: time.Now().UTC(),
	}, nil
}

// Execute executes a command.
func (s *trustedSandbox) Execute(ctx context.Context, cmd Command) (*Result, error) {
	if cmd.ID == "" {
		cmd.ID = string(utils.GenerateID())
	}
	s.beginRun()
	defer s.endRun()

	// Create a new context with timeout if specified
	runCtx, runCancel := context.WithCancel(ctx)
	defer runCancel()
	execCtx := runCtx
	var timeoutCancel context.CancelFunc
	if cmd.Timeout > 0 {
		execCtx, timeoutCancel = context.WithTimeout(runCtx, cmd.Timeout)
		defer timeoutCancel()
	}

	// Build command
	execCmd := exec.CommandContext(execCtx, cmd.Exec, cmd.Args...)
	if cmd.WorkingDir != "" {
		execCmd.Dir = cmd.WorkingDir
	}

	// Set environment
	if len(cmd.Env) > 0 {
		execCmd.Env = cmd.Env
	}

	// Capture stdout and stderr
	var stdoutBuf, stderrBuf bytes.Buffer
	execCmd.Stdout = &stdoutBuf
	execCmd.Stderr = &stderrBuf

	// Set stdin if provided
	if len(cmd.Stdin) > 0 {
		execCmd.Stdin = bytes.NewReader(cmd.Stdin)
	}

	// Track process
	processCancel := func() {
		if timeoutCancel != nil {
			timeoutCancel()
		}
		runCancel()
	}
	processInfo := &processInfo{
		started: time.Now().UTC(),
		ctx:     runCtx,
		cancel:  processCancel,
	}

	s.mutex.Lock()
	s.processes[string(cmd.ID)] = processInfo
	s.mutex.Unlock()
	defer func() {
		s.mutex.Lock()
		delete(s.processes, string(cmd.ID))
		s.mutex.Unlock()
		processCancel()
	}()

	// Execute
	startTime := time.Now()
	err := execCmd.Run()
	duration := time.Since(startTime)

	// Build result
	result := &Result{
		CommandID:     cmd.ID,
		Stdout:        stdoutBuf.Bytes(),
		Stderr:        stderrBuf.Bytes(),
		Duration:      duration,
		SandboxID:     s.id,
		SecurityLevel: LevelTrusted,
	}

	if execCmd.ProcessState != nil {
		result.ExitCode = execCmd.ProcessState.ExitCode()
		result.Success = result.ExitCode == 0
	}

	// Build metrics
	result.Metrics = &ExecutionMetrics{
		CPUMilliseconds: duration.Milliseconds(),
	}

	if err != nil {
		result.Error = fmt.Errorf("command execution failed: %w", err)
	}

	return result, nil
}

// ExecuteStreaming executes a command with streaming output.
func (s *trustedSandbox) ExecuteStreaming(
	ctx context.Context,
	cmd Command,
	onStdout func(data []byte),
	onStderr func(data []byte),
	onProgress func(progress float64),
) (*Result, error) {
	if cmd.ID == "" {
		cmd.ID = string(utils.GenerateID())
	}
	s.beginRun()
	defer s.endRun()

	// Create a new context with timeout if specified
	runCtx, runCancel := context.WithCancel(ctx)
	defer runCancel()
	execCtx := runCtx
	var timeoutCancel context.CancelFunc
	if cmd.Timeout > 0 {
		execCtx, timeoutCancel = context.WithTimeout(runCtx, cmd.Timeout)
		defer timeoutCancel()
	}

	// Build command
	execCmd := exec.CommandContext(execCtx, cmd.Exec, cmd.Args...)
	if cmd.WorkingDir != "" {
		execCmd.Dir = cmd.WorkingDir
	}

	// Set environment
	if len(cmd.Env) > 0 {
		execCmd.Env = cmd.Env
	}

	// Create pipes for stdout and stderr
	stdoutPipe, err := execCmd.StdoutPipe()
	if err != nil {
		return nil, fmt.Errorf("failed to create stdout pipe: %w", err)
	}

	stderrPipe, err := execCmd.StderrPipe()
	if err != nil {
		stdoutPipe.Close()
		return nil, fmt.Errorf("failed to create stderr pipe: %w", err)
	}

	// Set stdin if provided
	if len(cmd.Stdin) > 0 {
		execCmd.Stdin = bytes.NewReader(cmd.Stdin)
	}

	// Track process
	processCancel := func() {
		if timeoutCancel != nil {
			timeoutCancel()
		}
		runCancel()
	}
	processInfo := &processInfo{
		started: time.Now().UTC(),
		ctx:     runCtx,
		cancel:  processCancel,
	}

	s.mutex.Lock()
	s.processes[string(cmd.ID)] = processInfo
	s.mutex.Unlock()
	defer func() {
		s.mutex.Lock()
		delete(s.processes, string(cmd.ID))
		s.mutex.Unlock()
		processCancel()
	}()

	// Start command
	if err := execCmd.Start(); err != nil {
		stdoutPipe.Close()
		stderrPipe.Close()
		return nil, fmt.Errorf("failed to start command: %w", err)
	}

	startTime := time.Now()

	// Collect output concurrently
	var stdoutBuf, stderrBuf bytes.Buffer
	var stdoutWg, stderrWg sync.WaitGroup

	// Stream stdout
	stdoutWg.Add(1)
	go func() {
		defer stdoutWg.Done()
		defer stdoutPipe.Close()
		buf := make([]byte, 4096)
		for {
			n, err := stdoutPipe.Read(buf)
			if n > 0 {
				data := make([]byte, n)
				copy(data, buf[:n])
				stdoutBuf.Write(data)
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
	stderrWg.Add(1)
	go func() {
		defer stderrWg.Done()
		defer stderrPipe.Close()
		buf := make([]byte, 4096)
		for {
			n, err := stderrPipe.Read(buf)
			if n > 0 {
				data := make([]byte, n)
				copy(data, buf[:n])
				stderrBuf.Write(data)
				if onStderr != nil {
					onStderr(data)
				}
			}
			if err != nil {
				break
			}
		}
	}()

	// Send progress updates
	var progressDone chan struct{}
	if onProgress != nil && cmd.Timeout > 0 {
		progressDone = make(chan struct{})
		progressTicker := time.NewTicker(100 * time.Millisecond)
		defer progressTicker.Stop()

		go func() {
			for {
				select {
				case <-progressTicker.C:
					elapsed := time.Since(startTime).Seconds()
					total := cmd.Timeout.Seconds()
					if total > 0 {
						p := elapsed / total * 100
						if p > 100 {
							p = 100
						}
						onProgress(p)
					}
				case <-execCtx.Done():
					return
				case <-progressDone:
					return
				}
			}
		}()
	}

	// Wait for output collection
	stdoutWg.Wait()
	stderrWg.Wait()
	if progressDone != nil {
		close(progressDone)
	}

	// Wait for command to finish
	err = execCmd.Wait()
	duration := time.Since(startTime)

	// Build result
	result := &Result{
		CommandID:     cmd.ID,
		Stdout:        stdoutBuf.Bytes(),
		Stderr:        stderrBuf.Bytes(),
		Duration:      duration,
		SandboxID:     s.id,
		SecurityLevel: LevelTrusted,
	}

	if execCmd.ProcessState != nil {
		result.ExitCode = execCmd.ProcessState.ExitCode()
		result.Success = result.ExitCode == 0
	}

	// Build metrics
	result.Metrics = &ExecutionMetrics{
		CPUMilliseconds: duration.Milliseconds(),
	}

	if err != nil {
		result.Error = fmt.Errorf("command execution failed: %w", err)
		processCancel()
	}

	// Send final progress
	if onProgress != nil {
		if result.Success {
			onProgress(100)
		} else {
			onProgress(0)
		}
	}

	return result, nil
}

// Cancel cancels a running command.
func (s *trustedSandbox) Cancel(commandID string) error {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	process, ok := s.processes[string(commandID)]
	if !ok {
		return fmt.Errorf("command not found: %s", commandID)
	}

	if process.cancel != nil {
		process.cancel()
	}
	return nil
}

// Cleanup cleans up sandbox resources.
func (s *trustedSandbox) Cleanup() error {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	var errs []error

	// Kill all running processes
	for _, process := range s.processes {
		if process.cancel != nil {
			process.cancel()
		}
	}

	// Clear processes
	s.processes = make(map[string]*processInfo)

	if len(errs) > 0 {
		return fmt.Errorf("cleanup errors: %v", errs)
	}

	return nil
}

// Info returns sandbox information.
func (s *trustedSandbox) Info() SandboxInfo {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	return SandboxInfo{
		ID:          s.id,
		Level:       LevelTrusted,
		State:       s.state,
		CreatedAt:   s.createdAt,
		ActiveTasks: len(s.processes),
	}
}

// Level returns security level.
func (s *trustedSandbox) Level() SecurityLevel {
	return LevelTrusted
}

// Filesystem returns a legacy host filesystem accessor.
func (s *trustedSandbox) Filesystem() Filesystem {
	return newLegacyFilesystem(s.tempDir)
}

// PortForwarder returns a no-op port forwarder.
func (s *trustedSandbox) PortForwarder() PortForwarder {
	return defaultNoopPortForwarder
}

func (s *trustedSandbox) beginRun() {
	s.mutex.Lock()
	s.running++
	s.state = "running"
	s.mutex.Unlock()
}

func (s *trustedSandbox) endRun() {
	s.mutex.Lock()
	if s.running > 0 {
		s.running--
	}
	if s.running == 0 {
		s.state = "idle"
	}
	s.mutex.Unlock()
}
