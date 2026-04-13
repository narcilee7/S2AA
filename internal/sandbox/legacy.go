package sandbox

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
)

// legacyFilesystem provides a basic host-filesystem implementation for legacy sandboxes.
// It does NOT enforce capability boundaries and should only be used during migration.
type legacyFilesystem struct {
	baseDir string
}

func newLegacyFilesystem(baseDir string) *legacyFilesystem {
	return &legacyFilesystem{baseDir: baseDir}
}

func (fs *legacyFilesystem) resolve(path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(fs.baseDir, path)
}

func (fs *legacyFilesystem) ReadFile(ctx context.Context, path string) ([]byte, error) {
	return os.ReadFile(fs.resolve(path))
}

func (fs *legacyFilesystem) WriteFile(ctx context.Context, path string, data []byte, perm os.FileMode) error {
	resolved := fs.resolve(path)
	if err := os.MkdirAll(filepath.Dir(resolved), 0755); err != nil {
		return err
	}
	return os.WriteFile(resolved, data, perm)
}

func (fs *legacyFilesystem) ListFiles(ctx context.Context, path string) ([]FileInfo, error) {
	entries, err := os.ReadDir(fs.resolve(path))
	if err != nil {
		return nil, err
	}
	result := make([]FileInfo, 0, len(entries))
	for _, e := range entries {
		info, err := e.Info()
		if err != nil {
			continue
		}
		result = append(result, FileInfo{
			Name:    info.Name(),
			Path:    filepath.Join(path, info.Name()),
			Size:    info.Size(),
			Mode:    info.Mode(),
			ModTime: info.ModTime(),
			IsDir:   info.IsDir(),
		})
	}
	return result, nil
}

func (fs *legacyFilesystem) DeleteFile(ctx context.Context, path string) error {
	return os.RemoveAll(fs.resolve(path))
}

func (fs *legacyFilesystem) MkdirAll(ctx context.Context, path string, perm os.FileMode) error {
	return os.MkdirAll(fs.resolve(path), perm)
}

func (fs *legacyFilesystem) Stat(ctx context.Context, path string) (*FileInfo, error) {
	info, err := os.Stat(fs.resolve(path))
	if err != nil {
		return nil, err
	}
	return &FileInfo{
		Name:    info.Name(),
		Path:    path,
		Size:    info.Size(),
		Mode:    info.Mode(),
		ModTime: info.ModTime(),
		IsDir:   info.IsDir(),
	}, nil
}

func (fs *legacyFilesystem) UploadFile(ctx context.Context, hostPath, sandboxPath string) error {
	data, err := os.ReadFile(hostPath)
	if err != nil {
		return err
	}
	return fs.WriteFile(ctx, sandboxPath, data, 0644)
}

func (fs *legacyFilesystem) DownloadFile(ctx context.Context, sandboxPath, hostPath string) error {
	data, err := fs.ReadFile(ctx, sandboxPath)
	if err != nil {
		return err
	}
	return os.WriteFile(hostPath, data, 0644)
}

// noopPortForwarder is a PortForwarder that always returns an error.
type noopPortForwarder struct{}

func (n *noopPortForwarder) ExposePort(ctx context.Context, containerPort int) (string, func(), error) {
	return "", nil, fmt.Errorf("port forwarding not implemented for legacy sandbox")
}

func (n *noopPortForwarder) ListExposedPorts() []PortMapping {
	return nil
}

var defaultNoopPortForwarder PortForwarder = &noopPortForwarder{}
