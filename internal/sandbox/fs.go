package sandbox

import (
	"context"
	"os"
	"time"
)

// FileInfo represents metadata about a file or directory in a sandbox.
type FileInfo struct {
	Name    string
	Path    string
	Size    int64
	Mode    os.FileMode
	ModTime time.Time
	IsDir   bool
}

// Filesystem defines file operations within a sandbox.
// Implementations must respect the sandbox's capability boundaries.
type Filesystem interface {
	// ReadFile reads the entire contents of a file.
	ReadFile(ctx context.Context, path string) ([]byte, error)

	// WriteFile writes data to a file, creating it if necessary.
	WriteFile(ctx context.Context, path string, data []byte, perm os.FileMode) error

	// ListFiles returns entries in a directory.
	ListFiles(ctx context.Context, path string) ([]FileInfo, error)

	// DeleteFile removes a file or empty directory.
	DeleteFile(ctx context.Context, path string) error

	// MkdirAll creates a directory and its parents.
	MkdirAll(ctx context.Context, path string, perm os.FileMode) error

	// Stat returns file metadata without reading contents.
	Stat(ctx context.Context, path string) (*FileInfo, error)

	// UploadFile copies a file from the host into the sandbox.
	UploadFile(ctx context.Context, hostPath, sandboxPath string) error

	// DownloadFile copies a file from the sandbox to the host.
	DownloadFile(ctx context.Context, sandboxPath, hostPath string) error
}
