package sandbox

import (
	"context"
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestFactory(t *testing.T) {
	f, err := NewFactory(nil)
	if err != nil {
		t.Fatalf("Failed to create factory: %v", err)
	}
	defer f.Close()

	if f.BaseDir() == "" {
		t.Error("BaseDir should not be empty")
	}

	if f.TempDir() == "" {
		t.Error("TempDir should not be empty")
	}
}

func TestCreateSandboxL1(t *testing.T) {
	f, err := NewFactory(nil)
	if err != nil {
		t.Fatalf("Failed to create factory: %v", err)
	}
	defer f.Close()

	sandbox, err := f.CreateSandbox(LevelTrusted, nil, nil)
	if err != nil {
		t.Fatalf("Failed to create L1 sandbox: %v", err)
	}

	info := sandbox.Info()
	if info.Level != LevelTrusted {
		t.Errorf("Expected level %d, got %d", LevelTrusted, info.Level)
	}

	if sandbox.Level() != LevelTrusted {
		t.Errorf("Expected Level() to return %d, got %d", LevelTrusted, sandbox.Level())
	}

	if err := sandbox.Cleanup(); err != nil {
		t.Errorf("Failed to cleanup sandbox: %v", err)
	}
}

func TestCreateSandboxL2(t *testing.T) {
	f, err := NewFactory(nil)
	if err != nil {
		t.Fatalf("Failed to create factory: %v", err)
	}
	defer f.Close()

	sandbox, err := f.CreateSandbox(LevelRestricted, nil, nil)
	if err != nil {
		t.Fatalf("Failed to create L2 sandbox: %v", err)
	}

	info := sandbox.Info()
	if info.Level != LevelRestricted {
		t.Errorf("Expected level %d, got %d", LevelRestricted, info.Level)
	}

	if err := sandbox.Cleanup(); err != nil {
		t.Errorf("Failed to cleanup sandbox: %v", err)
	}
}

func TestCreateSandboxL3(t *testing.T) {
	f, err := NewFactory(nil)
	if err != nil {
		t.Fatalf("Failed to create factory: %v", err)
	}
	defer f.Close()

	sandbox, err := f.CreateSandbox(LevelIsolated, nil, nil)
	// L3 sandbox is currently a placeholder - it should succeed in creation
	if err != nil {
		t.Fatalf("Failed to create L3 sandbox: %v", err)
	}
	_ = sandbox
}

func TestCreateSandboxL4(t *testing.T) {
	f, err := NewFactory(nil)
	if err != nil {
		t.Fatalf("Failed to create factory: %v", err)
	}
	defer f.Close()

	_, err = f.CreateSandbox(LevelSecure, nil, nil)
	if err == nil {
		t.Error("Expected error for L4 sandbox without endpoint")
	}
}

func TestExecuteL1(t *testing.T) {
	f, err := NewFactory(nil)
	if err != nil {
		t.Fatalf("Failed to create factory: %v", err)
	}
	defer f.Close()

	ctx := context.Background()
	cmd := *NewCommand("echo", "hello, world")

	result, err := f.ExecuteCommand(ctx, LevelTrusted, cmd)
	if err != nil {
		t.Fatalf("Failed to execute command: %v", err)
	}

	if !result.Success {
		t.Errorf("Expected success, got exit code %d", result.ExitCode)
	}

	if string(result.Stdout) != "hello, world\n" {
		t.Errorf("Expected 'hello, world\\n', got '%s'", string(result.Stdout))
	}

	if result.SecurityLevel != LevelTrusted {
		t.Errorf("Expected security level %d, got %d", LevelTrusted, result.SecurityLevel)
	}
}

func TestExecuteL1WithTimeout(t *testing.T) {
	f, err := NewFactory(nil)
	if err != nil {
		t.Fatalf("Failed to create factory: %v", err)
	}
	defer f.Close()

	ctx := context.Background()
	cmd := *NewCommand("sleep", "10")
	cmd.Timeout = 100 * time.Millisecond

	result, err := f.ExecuteCommand(ctx, LevelTrusted, cmd)
	// Error is returned in result.Error, not as function return
	if result.Error == nil {
		t.Error("Expected result error due to timeout")
	}
}

func TestExecuteL1Multiple(t *testing.T) {
	f, err := NewFactory(nil)
	if err != nil {
		t.Fatalf("Failed to create factory: %v", err)
	}
	defer f.Close()

	ctx := context.Background()

	// Execute multiple commands concurrently
	results := make(chan *Result, 3)
	errors := make(chan error, 3)

	for i := 0; i < 3; i++ {
		go func(i int) {
			cmd := *NewCommand("echo", "test", strconv.Itoa(i))
			result, err := f.ExecuteCommand(ctx, LevelTrusted, cmd)
			if err != nil {
				errors <- err
				return
			}
			results <- result
		}(i)
	}

	// Collect results
	for i := 0; i < 3; i++ {
		select {
		case result := <-results:
			if !result.Success {
				t.Errorf("Command %d failed with exit code %d", i, result.ExitCode)
			}
		case err := <-errors:
			t.Errorf("Command execution failed: %v", err)
		case <-time.After(5 * time.Second):
			t.Fatal("Timeout waiting for command results")
		}
	}
}

func TestStreamingL1(t *testing.T) {
	f, err := NewFactory(nil)
	if err != nil {
		t.Fatalf("Failed to create factory: %v", err)
	}
	defer f.Close()

	ctx := context.Background()
	cmd := *NewCommand("echo", "hello")
	cmd.Timeout = 5 * time.Second

	var stdoutData []byte
	var stderrData []byte
	var progressValues []float64

	result, err := f.ExecuteCommandStreaming(
		ctx,
		LevelTrusted,
		cmd,
		func(data []byte) {
			stdoutData = append(stdoutData, data...)
		},
		func(data []byte) {
			stderrData = append(stderrData, data...)
		},
		func(progress float64) {
			progressValues = append(progressValues, progress)
		},
	)

	if err != nil {
		t.Fatalf("Failed to execute streaming command: %v", err)
	}

	if !result.Success {
		t.Errorf("Expected success, got exit code %d", result.ExitCode)
	}

	if string(stdoutData) != "hello\n" {
		t.Errorf("Expected 'hello\\n', got '%s'", string(stdoutData))
	}

	if len(progressValues) == 0 {
		t.Error("Expected progress updates")
	}
}

func TestStreamingL1ConcurrentProgressCallbacks(t *testing.T) {
	f, err := NewFactory(nil)
	if err != nil {
		t.Fatalf("Failed to create factory: %v", err)
	}
	defer f.Close()

	ctx := context.Background()
	const runs = 8
	errs := make(chan error, runs)
	var wg sync.WaitGroup

	for i := 0; i < runs; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()

			cmd := *NewCommand("sh", "-c", "echo start; sleep 0.15; echo done")
			cmd.ID = string(fmt.Sprintf("stream-%d", i))
			cmd.Timeout = time.Second

			var progressCount atomic.Int32
			result, err := f.ExecuteCommandStreaming(
				ctx,
				LevelTrusted,
				cmd,
				nil,
				nil,
				func(progress float64) {
					progressCount.Add(1)
				},
			)
			if err != nil {
				errs <- err
				return
			}
			if result == nil {
				errs <- fmt.Errorf("nil result for run %d", i)
				return
			}
			if progressCount.Load() == 0 {
				errs <- fmt.Errorf("missing progress callback for run %d", i)
			}
		}(i)
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Fatalf("streaming execution failed: %v", err)
	}
}

func TestSandboxCancelRunningCommand(t *testing.T) {
	f, err := NewFactory(nil)
	if err != nil {
		t.Fatalf("Failed to create factory: %v", err)
	}
	defer f.Close()

	sb, err := f.CreateSandbox(LevelTrusted, nil, nil)
	if err != nil {
		t.Fatalf("Failed to create sandbox: %v", err)
	}
	defer sb.Cleanup()

	cmd := *NewCommand("sleep", "5")
	cmd.ID = string("cancel-me")
	cmd.Timeout = 10 * time.Second

	resultCh := make(chan *Result, 1)
	errCh := make(chan error, 1)

	go func() {
		result, execErr := sb.Execute(context.Background(), cmd)
		if execErr != nil {
			errCh <- execErr
			return
		}
		resultCh <- result
	}()

	time.Sleep(150 * time.Millisecond)
	if err := sb.Cancel(cmd.ID); err != nil {
		t.Fatalf("Cancel failed: %v", err)
	}

	select {
	case execErr := <-errCh:
		t.Fatalf("Execute returned error: %v", execErr)
	case result := <-resultCh:
		if result == nil {
			t.Fatal("expected result, got nil")
		}
		if result.Error == nil {
			t.Fatal("expected result error after cancel")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("timeout waiting for canceled command result")
	}
}

func TestSandboxExecuteAssignsCommandID(t *testing.T) {
	f, err := NewFactory(nil)
	if err != nil {
		t.Fatalf("Failed to create factory: %v", err)
	}
	defer f.Close()

	sb, err := f.CreateSandbox(LevelTrusted, nil, nil)
	if err != nil {
		t.Fatalf("Failed to create sandbox: %v", err)
	}
	defer sb.Cleanup()

	cmd := *NewCommand("echo", "id-auto")
	cmd.ID = ""

	result, err := sb.Execute(context.Background(), cmd)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if result == nil {
		t.Fatal("expected result, got nil")
	}
	if result.CommandID == "" {
		t.Fatal("expected non-empty command id")
	}
}

func TestSandboxStateStaysRunningWithConcurrentCommands(t *testing.T) {
	f, err := NewFactory(nil)
	if err != nil {
		t.Fatalf("Failed to create factory: %v", err)
	}
	defer f.Close()

	sb, err := f.CreateSandbox(LevelTrusted, nil, nil)
	if err != nil {
		t.Fatalf("Failed to create sandbox: %v", err)
	}
	defer sb.Cleanup()

	cmd1 := *NewCommand("sleep", "1")
	cmd1.ID = "state-1"
	cmd2 := *NewCommand("sleep", "1")
	cmd2.ID = "state-2"

	done1 := make(chan *Result, 1)
	done2 := make(chan *Result, 1)

	go func() {
		result, _ := sb.Execute(context.Background(), cmd1)
		done1 <- result
	}()

	time.Sleep(100 * time.Millisecond)

	go func() {
		result, _ := sb.Execute(context.Background(), cmd2)
		done2 <- result
	}()

	time.Sleep(150 * time.Millisecond)
	info := sb.Info()
	if info.State != "running" {
		t.Fatalf("expected running state while commands execute, got %s", info.State)
	}
	if info.ActiveTasks < 2 {
		t.Fatalf("expected at least two active tasks, got %d", info.ActiveTasks)
	}

	<-done1

	time.Sleep(100 * time.Millisecond)
	info = sb.Info()
	if info.State != "running" {
		t.Fatalf("expected running state while one command still executes, got %s", info.State)
	}
	if info.ActiveTasks < 1 {
		t.Fatalf("expected at least one active task, got %d", info.ActiveTasks)
	}

	<-done2

	time.Sleep(50 * time.Millisecond)
	info = sb.Info()
	if info.State != "idle" {
		t.Fatalf("expected idle state after all commands complete, got %s", info.State)
	}
}

func TestCustomLimits(t *testing.T) {
	f, err := NewFactory(nil)
	if err != nil {
		t.Fatalf("Failed to create factory: %v", err)
	}
	defer f.Close()

	limits := &ResourceLimits{
		CPUMax:       1.0,
		MemoryBytes:  256 * 1024 * 1024,
		MaxProcesses: 50,
		MaxFiles:     512,
		Timeout:      2 * time.Minute,
	}

	sandbox, err := f.CreateSandbox(LevelTrusted, limits, nil)
	if err != nil {
		t.Fatalf("Failed to create sandbox with custom limits: %v", err)
	}

	info := sandbox.Info()
	if info.ID == "" {
		t.Error("Sandbox ID should not be empty")
	}

	if err := sandbox.Cleanup(); err != nil {
		t.Errorf("Failed to cleanup sandbox: %v", err)
	}
}

func TestCustomCapabilities(t *testing.T) {
	f, err := NewFactory(nil)
	if err != nil {
		t.Fatalf("Failed to create factory: %v", err)
	}
	defer f.Close()

	caps := &Capabilities{
		AllowedSyscalls: []string{"read", "write"},
		NetworkAccess:   NetworkBlockAll,
		AllowedDomains:  []string{"example.com"},
	}

	sandbox, err := f.CreateSandbox(LevelTrusted, nil, caps)
	if err != nil {
		t.Fatalf("Failed to create sandbox with custom capabilities: %v", err)
	}

	if err := sandbox.Cleanup(); err != nil {
		t.Errorf("Failed to cleanup sandbox: %v", err)
	}
}

func TestGetSandbox(t *testing.T) {
	f, err := NewFactory(nil)
	if err != nil {
		t.Fatalf("Failed to create factory: %v", err)
	}
	defer f.Close()

	sandbox, err := f.CreateSandbox(LevelTrusted, nil, nil)
	if err != nil {
		t.Fatalf("Failed to create sandbox: %v", err)
	}
	defer sandbox.Cleanup()

	info := sandbox.Info()

	retrieved, err := f.GetSandbox(info.ID)
	if err != nil {
		t.Fatalf("Failed to get sandbox: %v", err)
	}

	if retrieved.Info().ID != info.ID {
		t.Errorf("Expected ID %s, got %s", info.ID, retrieved.Info().ID)
	}

	if retrieved.Level() != LevelTrusted {
		t.Errorf("Expected level %d, got %d", LevelTrusted, retrieved.Level())
	}
}

func TestListSandboxes(t *testing.T) {
	f, err := NewFactory(nil)
	if err != nil {
		t.Fatalf("Failed to create factory: %v", err)
	}
	defer f.Close()

	// Create multiple sandboxes
	sandboxes := make([]Sandbox, 3)
	for i := 0; i < 3; i++ {
		s, err := f.CreateSandbox(LevelTrusted, nil, nil)
		if err != nil {
			t.Fatalf("Failed to create sandbox %d: %v", i, err)
		}
		sandboxes[i] = s
		defer s.Cleanup()
	}

	// List sandboxes
	list := f.ListSandboxes()
	if len(list) != 3 {
		t.Errorf("Expected 3 sandboxes, got %d", len(list))
	}
}

func TestSecurityLevelString(t *testing.T) {
	tests := []struct {
		level    SecurityLevel
		expected string
	}{
		{LevelTrusted, "trusted"},
		{LevelRestricted, "restricted"},
		{LevelIsolated, "isolated"},
		{LevelSecure, "secure"},
		{SecurityLevel(99), "unknown"},
	}

	for _, tt := range tests {
		if got := tt.level.String(); got != tt.expected {
			t.Errorf("Level %d: expected %s, got %s", tt.level, tt.expected, got)
		}
	}
}

func TestNetworkPolicyString(t *testing.T) {
	tests := []struct {
		policy   NetworkPolicy
		expected string
	}{
		{NetworkAllowAll, "allow-all"},
		{NetworkBlockAll, "block-all"},
		{NetworkWhitelist, "whitelist"},
		{NetworkBlacklist, "blacklist"},
		{NetworkLocalOnly, "local-only"},
		{NetworkPolicy(99), "unknown"},
	}

	for _, tt := range tests {
		if got := tt.policy.String(); got != tt.expected {
			t.Errorf("Policy %d: expected %s, got %s", tt.policy, tt.expected, got)
		}
	}
}

func TestDefaultResourceLimits(t *testing.T) {
	tests := []struct {
		level SecurityLevel
	}{
		{LevelTrusted},
		{LevelRestricted},
		{LevelIsolated},
		{LevelSecure},
	}

	for _, tt := range tests {
		limits := DefaultResourceLimits(tt.level)
		if limits == nil {
			t.Errorf("Expected non-nil limits for level %d", tt.level)
		}

		if err := limits.Validate(); err != nil {
			t.Errorf("Default limits for level %d are invalid: %v", tt.level, err)
		}
	}
}

func TestDefaultCapabilities(t *testing.T) {
	tests := []struct {
		level SecurityLevel
	}{
		{LevelTrusted},
		{LevelRestricted},
		{LevelIsolated},
		{LevelSecure},
	}

	for _, tt := range tests {
		caps := DefaultCapabilities(tt.level)
		if caps == nil {
			t.Errorf("Expected non-nil capabilities for level %d", tt.level)
		}
	}
}
