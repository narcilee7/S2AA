package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/mdlayher/vsock"
	"github.com/narcilee7/S2AA/api/sandboxpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// sandbox-agent runs inside a Firecracker microVM and exposes a gRPC
// SandboxService over vsock (port 8080 by default).

const defaultVsockPort = 8080

type agentServer struct {
	sandboxpb.UnimplementedSandboxServiceServer
	mu        sync.RWMutex
	running   map[string]*exec.Cmd
	cancelFns map[string]context.CancelFunc
}

func main() {
	port := defaultVsockPort
	if p := os.Getenv("VSOCK_PORT"); p != "" {
		if v, err := fmt.Sscanf(p, "%d", &port); err != nil || v != 1 {
			port = defaultVsockPort
		}
	}

	lis, err := vsock.Listen(uint32(port), nil)
	if err != nil {
		log.Fatalf("failed to listen on vsock:%d: %v", port, err)
	}

	srv := grpc.NewServer()
	sandboxpb.RegisterSandboxServiceServer(srv, &agentServer{
		running:   make(map[string]*exec.Cmd),
		cancelFns: make(map[string]context.CancelFunc),
	})

	log.Printf("sandbox-agent listening on vsock port %d", port)
	if err := srv.Serve(lis); err != nil {
		log.Fatalf("agent exited: %v", err)
	}
}

func (s *agentServer) Execute(ctx context.Context, req *sandboxpb.ExecuteRequest) (*sandboxpb.ExecuteResponse, error) {
	cmdCtx := ctx
	var cancel context.CancelFunc
	if req.TimeoutMs > 0 {
		cmdCtx, cancel = context.WithTimeout(ctx, time.Duration(req.TimeoutMs)*time.Millisecond)
		defer cancel()
	}

	cmd := exec.CommandContext(cmdCtx, req.Exec, req.Args...)
	cmd.Dir = req.WorkingDir
	if cmd.Dir == "" {
		cmd.Dir = "/workspace"
	}
	if len(req.Env) > 0 {
		cmd.Env = req.Env
	}
	if len(req.Stdin) > 0 {
		cmd.Stdin = bytes.NewReader(req.Stdin)
	}

	var stdoutBuf, stderrBuf bytes.Buffer
	cmd.Stdout = &stdoutBuf
	cmd.Stderr = &stderrBuf

	s.trackCommand(req.CommandId, cmd, cancel)
	start := time.Now()
	err := cmd.Run()
	duration := time.Since(start)
	s.untrackCommand(req.CommandId)

	exitCode := int32(0)
	success := true
	errMsg := ""
	if err != nil {
		success = false
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = int32(exitErr.ExitCode())
		} else {
			exitCode = -1
		}
		errMsg = err.Error()
	}

	return &sandboxpb.ExecuteResponse{
		CommandId:  req.CommandId,
		ExitCode:   exitCode,
		Success:    success,
		Stdout:     stdoutBuf.Bytes(),
		Stderr:     stderrBuf.Bytes(),
		Error:      errMsg,
		DurationMs: duration.Milliseconds(),
	}, nil
}

func (s *agentServer) ExecuteStream(req *sandboxpb.ExecuteRequest, stream grpc.ServerStreamingServer[sandboxpb.StreamChunk]) error {
	ctx := stream.Context()
	cmdCtx := ctx
	var cancel context.CancelFunc
	if req.TimeoutMs > 0 {
		cmdCtx, cancel = context.WithTimeout(ctx, time.Duration(req.TimeoutMs)*time.Millisecond)
		defer cancel()
	}

	cmd := exec.CommandContext(cmdCtx, req.Exec, req.Args...)
	cmd.Dir = req.WorkingDir
	if cmd.Dir == "" {
		cmd.Dir = "/workspace"
	}
	if len(req.Env) > 0 {
		cmd.Env = req.Env
	}
	if len(req.Stdin) > 0 {
		cmd.Stdin = bytes.NewReader(req.Stdin)
	}

	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		return status.Errorf(codes.Internal, "stdout pipe: %v", err)
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		return status.Errorf(codes.Internal, "stderr pipe: %v", err)
	}

	s.trackCommand(req.CommandId, cmd, cancel)
	start := time.Now()
	if err := cmd.Start(); err != nil {
		s.untrackCommand(req.CommandId)
		return status.Errorf(codes.Internal, "start failed: %v", err)
	}

	var wg sync.WaitGroup
	streamReader := func(r io.Reader, isStdout bool) {
		defer wg.Done()
		buf := make([]byte, 4096)
		for {
			n, err := r.Read(buf)
			if n > 0 {
				data := make([]byte, n)
				copy(data, buf[:n])
				chunk := sandboxpb.StreamChunk{}
				if isStdout {
					chunk.Payload = &sandboxpb.StreamChunk_Stdout{Stdout: data}
				} else {
					chunk.Payload = &sandboxpb.StreamChunk_Stderr{Stderr: data}
				}
				_ = stream.Send(&chunk)
			}
			if err != nil {
				break
			}
		}
	}

	wg.Add(2)
	go streamReader(stdoutPipe, true)
	go streamReader(stderrPipe, false)

	// Progress ticker
	var progressDone chan struct{}
	if req.TimeoutMs > 0 {
		progressDone = make(chan struct{})
		ticker := time.NewTicker(100 * time.Millisecond)
		go func() {
			defer ticker.Stop()
			total := float64(req.TimeoutMs)
			for {
				select {
				case <-ticker.C:
					elapsed := float64(time.Since(start).Milliseconds())
					p := elapsed / total * 100
					if p > 100 {
						p = 100
					}
					_ = stream.Send(&sandboxpb.StreamChunk{
						Payload: &sandboxpb.StreamChunk_Progress{Progress: p},
					})
				case <-progressDone:
					return
				case <-ctx.Done():
					return
				}
			}
		}()
	}

	execErr := cmd.Wait()
	duration := time.Since(start)
	wg.Wait()
	if progressDone != nil {
		close(progressDone)
	}
	s.untrackCommand(req.CommandId)

	exitCode := int32(0)
	success := true
	errMsg := ""
	if execErr != nil {
		success = false
		if exitErr, ok := execErr.(*exec.ExitError); ok {
			exitCode = int32(exitErr.ExitCode())
		} else {
			exitCode = -1
		}
		errMsg = execErr.Error()
	}

	result := &sandboxpb.ExecuteResponse{
		CommandId:  req.CommandId,
		ExitCode:   exitCode,
		Success:    success,
		DurationMs: duration.Milliseconds(),
		Error:      errMsg,
	}
	return stream.Send(&sandboxpb.StreamChunk{
		Payload: &sandboxpb.StreamChunk_Result{Result: result},
	})
}

func (s *agentServer) Cancel(ctx context.Context, req *sandboxpb.CancelRequest) (*sandboxpb.CancelResponse, error) {
	s.mu.Lock()
	cancel, ok := s.cancelFns[req.CommandId]
	s.mu.Unlock()
	if ok && cancel != nil {
		cancel()
		return &sandboxpb.CancelResponse{Success: true}, nil
	}
	return &sandboxpb.CancelResponse{Success: false}, nil
}

func (s *agentServer) ReadFile(ctx context.Context, req *sandboxpb.FileRequest) (*sandboxpb.ReadFileResponse, error) {
	data, err := os.ReadFile(req.Path)
	if err != nil {
		return &sandboxpb.ReadFileResponse{Success: false, Error: err.Error()}, nil
	}
	return &sandboxpb.ReadFileResponse{Success: true, Data: data}, nil
}

func (s *agentServer) WriteFile(ctx context.Context, req *sandboxpb.WriteFileRequest) (*sandboxpb.FileResponse, error) {
	if err := os.MkdirAll(filepath.Dir(req.Path), 0755); err != nil {
		return &sandboxpb.FileResponse{Success: false, Error: err.Error()}, nil
	}
	if err := os.WriteFile(req.Path, req.Data, os.FileMode(req.Mode)); err != nil {
		return &sandboxpb.FileResponse{Success: false, Error: err.Error()}, nil
	}
	return &sandboxpb.FileResponse{Success: true}, nil
}

func (s *agentServer) ListFiles(ctx context.Context, req *sandboxpb.FileRequest) (*sandboxpb.ListFilesResponse, error) {
	entries, err := os.ReadDir(req.Path)
	if err != nil {
		return &sandboxpb.ListFilesResponse{Success: false, Error: err.Error()}, nil
	}
	infos := make([]*sandboxpb.FileInfoMsg, 0, len(entries))
	for _, e := range entries {
		fi, err := e.Info()
		if err != nil {
			continue
		}
		infos = append(infos, &sandboxpb.FileInfoMsg{
			Name:        fi.Name(),
			Path:        filepath.Join(req.Path, fi.Name()),
			Size:        fi.Size(),
			Mode:        uint32(fi.Mode()),
			ModTimeUnix: fi.ModTime().Unix(),
			IsDir:       fi.IsDir(),
		})
	}
	return &sandboxpb.ListFilesResponse{Success: true, Entries: infos}, nil
}

func (s *agentServer) DeleteFile(ctx context.Context, req *sandboxpb.FileRequest) (*sandboxpb.FileResponse, error) {
	if err := os.RemoveAll(req.Path); err != nil {
		return &sandboxpb.FileResponse{Success: false, Error: err.Error()}, nil
	}
	return &sandboxpb.FileResponse{Success: true}, nil
}

func (s *agentServer) MkdirAll(ctx context.Context, req *sandboxpb.MkdirRequest) (*sandboxpb.FileResponse, error) {
	if err := os.MkdirAll(req.Path, os.FileMode(req.Mode)); err != nil {
		return &sandboxpb.FileResponse{Success: false, Error: err.Error()}, nil
	}
	return &sandboxpb.FileResponse{Success: true}, nil
}

func (s *agentServer) Stat(ctx context.Context, req *sandboxpb.FileRequest) (*sandboxpb.StatResponse, error) {
	fi, err := os.Stat(req.Path)
	if err != nil {
		return &sandboxpb.StatResponse{Success: false, Error: err.Error()}, nil
	}
	return &sandboxpb.StatResponse{
		Success: true,
		Info: &sandboxpb.FileInfoMsg{
			Name:        fi.Name(),
			Path:        req.Path,
			Size:        fi.Size(),
			Mode:        uint32(fi.Mode()),
			ModTimeUnix: fi.ModTime().Unix(),
			IsDir:       fi.IsDir(),
		},
	}, nil
}

func (s *agentServer) ExposePort(ctx context.Context, req *sandboxpb.PortRequest) (*sandboxpb.PortResponse, error) {
	// Inside the guest we only validate intent; the host owns the actual mapping.
	return &sandboxpb.PortResponse{
		Success:   true,
		HostPort:  req.ContainerPort,
		PublicUrl: fmt.Sprintf("http://localhost:%d", req.ContainerPort),
	}, nil
}

func (s *agentServer) GetStatus(ctx context.Context, req *sandboxpb.StatusRequest) (*sandboxpb.StatusResponse, error) {
	s.mu.RLock()
	n := int32(len(s.running))
	s.mu.RUnlock()
	return &sandboxpb.StatusResponse{
		State:       "running",
		ActiveTasks: n,
		UptimeMs:    0,
	}, nil
}

func (s *agentServer) trackCommand(id string, cmd *exec.Cmd, cancel context.CancelFunc) {
	s.mu.Lock()
	s.running[id] = cmd
	if cancel != nil {
		s.cancelFns[id] = cancel
	}
	s.mu.Unlock()
}

func (s *agentServer) untrackCommand(id string) {
	s.mu.Lock()
	delete(s.running, id)
	delete(s.cancelFns, id)
	s.mu.Unlock()
}
