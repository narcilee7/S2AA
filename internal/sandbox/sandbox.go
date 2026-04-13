package sandbox

import (
	"context"
	"io"
	"time"
)

// sandbox is the internal interface for sandbox implementations.
type sandbox interface {
	Execute(ctx context.Context, cmd Command) (*Result, error)
	ExecuteStreaming(
		ctx context.Context,
		cmd Command,
		onStdout func(data []byte),
		onStderr func(data []byte),
		onProgress func(progress float64),
	) (*Result, error)
	Cancel(commandID string) error
	Cleanup() error
	Info() SandboxInfo
	Level() SecurityLevel
	Filesystem() Filesystem
	PortForwarder() PortForwarder
	Snapshot(snapshotID string) error
	Restore(snapshotID string) error
}

// Sandbox is the public interface for secure execution environment.
type Sandbox interface {
	// Execute executes a command and returns a result.
	Execute(ctx context.Context, cmd Command) (*Result, error)

	// ExecuteStreaming executes a command with streaming output callbacks.
	// Suitable for long-running tasks.
	ExecuteStreaming(
		ctx context.Context,
		cmd Command,
		onStdout func(data []byte),
		onStderr func(data []byte),
		onProgress func(progress float64),
	) (*Result, error)

	// Cancel cancels a running command.
	Cancel(commandID string) error

	// Cleanup cleans up sandbox resources.
	Cleanup() error

	// Info returns sandbox information.
	Info() SandboxInfo

	// Level returns the security level.
	Level() SecurityLevel

	// Filesystem returns the sandbox filesystem accessor.
	Filesystem() Filesystem

	// PortForwarder returns the sandbox port forwarder.
	PortForwarder() PortForwarder

	// Snapshot creates a snapshot of the sandbox state.
	Snapshot(snapshotID string) error

	// Restore restores the sandbox from a snapshot.
	Restore(snapshotID string) error
}

// StreamingOptions contains options for streaming execution.
type StreamingOptions struct {
	// ChunkSize is the buffer size for streaming (default: 4KB)
	ChunkSize int

	// ProgressInterval is the interval for progress callbacks (default: 100ms)
	ProgressInterval time.Duration
}

// DefaultStreamingOptions returns default streaming options.
func DefaultStreamingOptions() *StreamingOptions {
	return &StreamingOptions{
		ChunkSize:        4 * 1024, // 4KB
		ProgressInterval: 100 * time.Millisecond,
	}
}

// WriteCloser combines io.Writer with Close method.
type WriteCloser interface {
	io.Writer
	Close() error
}
