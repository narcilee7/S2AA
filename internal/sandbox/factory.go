// Package execution provides secure execution environment with progressive sandboxing.
package sandbox

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/narcilee7/S2AA/internal/audit"
	"github.com/narcilee7/S2AA/internal/utils"
)

// Factory creates and manages sandboxes.
type Factory struct {
	baseDir      string
	tempDir      string
	config       *FactoryConfig
	mutex        sync.RWMutex
	sandboxes    map[string]sandbox
	persistent   map[string]bool
}

// FactoryConfig contains configuration for sandbox factory.
type FactoryConfig struct {
	// BaseDir is the base directory for sandbox data (default: /tmp/metis-sandbox)
	BaseDir string

	// TempDir is the temporary directory for sandbox temp files (default: /tmp/metis-temp)
	TempDir string

	// EnableCgroup enables cgroup support for L2 (default: true)
	EnableCgroup bool

	// ContainerRuntime is the container runtime for L3: runc, podman, docker (default: runc)
	ContainerRuntime string

	// RemoteEndpoint is the remote sandbox endpoint for L4
	RemoteEndpoint string

	// IsolationBackend selects the underlying isolation technology.
	// Values: "legacy" | "microvm" | "auto". Default: "legacy".
	IsolationBackend string
}

type DirString string

const (
	DirBase DirString = ("/tmp/metis-sandbox")
	DirTemp DirString = ("/tmp/metis-temp")
)

// DefaultFactoryConfig returns default factory configuration.
func DefaultFactoryConfig() *FactoryConfig {
	return &FactoryConfig{
		BaseDir:          string(DirBase),
		TempDir:          string(DirTemp),
		EnableCgroup:     true,
		ContainerRuntime: "runc",
		IsolationBackend: "legacy",
	}
}

// NewFactory creates a new sandbox factory.
func NewFactory(config *FactoryConfig) (*Factory, error) {
	if config == nil {
		config = DefaultFactoryConfig()
	}

	// Set defaults
	if config.BaseDir == "" {
		config.BaseDir = string(DirBase)
	}
	if config.TempDir == "" {
		config.TempDir = string(DirTemp)
	}
	if config.ContainerRuntime == "" {
		config.ContainerRuntime = "runc"
	}
	if config.IsolationBackend == "" {
		config.IsolationBackend = "legacy"
	}

	// Create directories
	for _, dir := range []string{config.BaseDir, config.TempDir} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create directory %s: %w", dir, err)
		}
	}

	// Make paths absolute
	baseDir, err := filepath.Abs(config.BaseDir)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve base directory: %w", err)
	}

	tempDir, err := filepath.Abs(config.TempDir)
	if err != nil {
		return nil, fmt.Errorf("failed to resolve temp directory: %w", err)
	}

	return &Factory{
		baseDir:    baseDir,
		tempDir:    tempDir,
		config:     config,
		sandboxes:  make(map[string]sandbox),
		persistent: make(map[string]bool),
	}, nil
}

// SandboxOptions contains optional parameters for sandbox creation.
type SandboxOptions struct {
	Level        SecurityLevel
	Limits       *ResourceLimits
	Capabilities *Capabilities
	Persistent   bool
	WorkspaceDir string // optional, auto-generated if empty
}

// CreateSandbox creates a sandbox with specified security level.
func (f *Factory) CreateSandbox(
	level SecurityLevel,
	limits *ResourceLimits,
	caps *Capabilities,
) (Sandbox, error) {
	return f.CreateSandboxWithOptions(SandboxOptions{
		Level:        level,
		Limits:       limits,
		Capabilities: caps,
	})
}

// CreateSandboxWithOptions creates a sandbox with advanced options.
func (f *Factory) CreateSandboxWithOptions(opts SandboxOptions) (Sandbox, error) {
	level := opts.Level
	limits := opts.Limits
	caps := opts.Capabilities

	// Use default limits and capabilities
	if limits == nil {
		limits = DefaultResourceLimits(level)
	}
	if err := limits.Validate(); err != nil {
		return nil, fmt.Errorf("invalid resource limits: %w", err)
	}

	if caps == nil {
		caps = DefaultCapabilities(level)
	}

	var sb sandbox
	var err error

	switch level {
	case LevelTrusted:
		sb, err = newTrustedSandbox(limits, caps, f.tempDir)

	case LevelRestricted:
		sb, err = newRestrictedSandbox(
			limits,
			caps,
			f.tempDir,
			f.baseDir,
			f.config.EnableCgroup,
		)

	case LevelIsolated:
		if f.config.IsolationBackend == "microvm" {
			sb, err = newMicroVMSandbox(limits, caps, f.baseDir, audit.DefaultNoOp())
		} else {
			sb, err = newIsolatedSandbox(
				limits,
				caps,
				f.baseDir,
				f.config.ContainerRuntime,
			)
		}

	case LevelSecure:
		if f.config.IsolationBackend == "microvm" {
			sb, err = newMicroVMSandbox(limits, caps, f.baseDir, audit.DefaultNoOp())
		} else {
			if f.config.RemoteEndpoint == "" {
				return nil, fmt.Errorf("remote endpoint required for L4 sandbox")
			}
			sb, err = newSecureSandbox(
				limits,
				caps,
				f.config.RemoteEndpoint,
			)
		}

	default:
		return nil, fmt.Errorf("unknown security level: %d", level)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to create %s sandbox: %w", level.String(), err)
	}

	// Register sandbox
	info := sb.Info()
	f.mutex.Lock()
	f.sandboxes[info.ID] = sb
	f.persistent[info.ID] = opts.Persistent
	f.mutex.Unlock()

	return &sandboxWrapper{sb: sb, persistent: opts.Persistent}, nil
}

// ResumeSandbox retrieves an existing sandbox by ID for reuse.
func (f *Factory) ResumeSandbox(id string) (Sandbox, error) {
	return f.GetSandbox(id)
}

// GetSandbox retrieves a sandbox by ID.
func (f *Factory) GetSandbox(id string) (Sandbox, error) {
	f.mutex.RLock()
	defer f.mutex.RUnlock()

	sb, ok := f.sandboxes[id]
	if !ok {
		return nil, fmt.Errorf("sandbox not found: %s", id)
	}

	return &sandboxWrapper{sb: sb, persistent: f.persistent[id]}, nil
}

// ListSandboxes returns all registered sandboxes.
func (f *Factory) ListSandboxes() []SandboxInfo {
	f.mutex.RLock()
	defer f.mutex.RUnlock()

	infos := make([]SandboxInfo, 0, len(f.sandboxes))
	for _, sb := range f.sandboxes {
		infos = append(infos, sb.Info())
	}

	return infos
}

// CleanupAll cleans up all sandboxes. Persistent sandboxes are skipped unless force=true.
func (f *Factory) CleanupAll() error {
	return f.cleanupAllInternal(false)
}

// ForceCleanupAll cleans up all sandboxes including persistent ones.
func (f *Factory) ForceCleanupAll() error {
	return f.cleanupAllInternal(true)
}

func (f *Factory) cleanupAllInternal(force bool) error {
	f.mutex.Lock()
	defer f.mutex.Unlock()

	var errs []error
	for id, sb := range f.sandboxes {
		if !force && f.persistent[id] {
			continue
		}
		if err := sb.Cleanup(); err != nil {
			errs = append(errs, fmt.Errorf("failed to cleanup sandbox %s: %w", id, err))
		}
		delete(f.sandboxes, id)
		delete(f.persistent, id)
	}

	if len(errs) > 0 {
		return fmt.Errorf("cleanup errors: %v", errs)
	}

	return nil
}

// Close implements io.Closer for convenient cleanup.
func (f *Factory) Close() error {
	return f.cleanupAllInternal(false)
}

// BaseDir returns the base directory.
func (f *Factory) BaseDir() string {
	return f.baseDir
}

// TempDir returns the temp directory.
func (f *Factory) TempDir() string {
	return f.tempDir
}

// Config returns the factory configuration.
func (f *Factory) Config() *FactoryConfig {
	return f.config
}

// ExecuteCommand is a convenience method to execute a command in a sandbox.
// Creates a temporary sandbox for execution and cleans it up after.
func (f *Factory) ExecuteCommand(
	ctx context.Context,
	level SecurityLevel,
	cmd Command,
) (*Result, error) {
	sb, err := f.CreateSandbox(level, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create sandbox: %w", err)
	}
	defer sb.Cleanup()

	// Set command ID if not set
	if cmd.ID == "" {
		cmd.ID = string(utils.GenerateID())
	}

	return sb.Execute(ctx, cmd)
}

// ExecuteCommandStreaming is a convenience method for streaming execution.
func (f *Factory) ExecuteCommandStreaming(
	ctx context.Context,
	level SecurityLevel,
	cmd Command,
	onStdout func(data []byte),
	onStderr func(data []byte),
	onProgress func(progress float64),
) (*Result, error) {
	sb, err := f.CreateSandbox(level, nil, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create sandbox: %w", err)
	}
	defer sb.Cleanup()

	// Set command ID if not set
	if cmd.ID == "" {
		cmd.ID = string(utils.GenerateID())
	}

	return sb.ExecuteStreaming(ctx, cmd, onStdout, onStderr, onProgress)
}

// sandboxWrapper wraps internal sandbox implementation.
type sandboxWrapper struct {
	sb         sandbox
	persistent bool
}

func (w *sandboxWrapper) Execute(ctx context.Context, cmd Command) (*Result, error) {
	return w.sb.Execute(ctx, cmd)
}

func (w *sandboxWrapper) ExecuteStreaming(
	ctx context.Context,
	cmd Command,
	onStdout func(data []byte),
	onStderr func(data []byte),
	onProgress func(progress float64),
) (*Result, error) {
	return w.sb.ExecuteStreaming(ctx, cmd, onStdout, onStderr, onProgress)
}

func (w *sandboxWrapper) Cancel(commandID string) error {
	return w.sb.Cancel(commandID)
}

func (w *sandboxWrapper) Cleanup() error {
	if w.persistent {
		return nil
	}
	return w.sb.Cleanup()
}

func (w *sandboxWrapper) Info() SandboxInfo {
	info := w.sb.Info()
	info.Persistent = w.persistent
	return info
}

func (w *sandboxWrapper) Level() SecurityLevel {
	return w.sb.Level()
}

func (w *sandboxWrapper) Filesystem() Filesystem {
	return w.sb.Filesystem()
}

func (w *sandboxWrapper) PortForwarder() PortForwarder {
	return w.sb.PortForwarder()
}

func (w *sandboxWrapper) Snapshot(snapshotID string) error {
	return w.sb.Snapshot(snapshotID)
}

func (w *sandboxWrapper) Restore(snapshotID string) error {
	return w.sb.Restore(snapshotID)
}
