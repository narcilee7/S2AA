package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/narcilee7/S2AA/internal/sandbox"
)

// sandbox-agent runs inside a Firecracker microVM and exposes an HTTP API
// over the primary network interface (0.0.0.0:8080). Firecracker vsock
// forwards host connections to this port.

var (
	mu        sync.Mutex
	running   map[string]*exec.Cmd
	cancelFns map[string]context.CancelFunc
)

func main() {
	running = make(map[string]*exec.Cmd)
	cancelFns = make(map[string]context.CancelFunc)

	mux := http.NewServeMux()
	mux.HandleFunc("/execute", handleExecute)
	mux.HandleFunc("/read", handleRead)
	mux.HandleFunc("/write", handleWrite)
	mux.HandleFunc("/list", handleList)
	mux.HandleFunc("/delete", handleDelete)
	mux.HandleFunc("/port", handlePort)
	mux.HandleFunc("/cancel", handleCancel)
	mux.HandleFunc("/status", handleStatus)
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	addr := ":8080"
	log.Printf("sandbox-agent listening on %s", addr)
	if err := http.ListenAndServe(addr, mux); err != nil {
		log.Fatalf("agent exited: %v", err)
	}
}

func handleExecute(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req sandbox.AgentExecuteRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, sandbox.AgentExecuteResponse{Success: false, Error: err.Error()})
		return
	}

	ctx := context.Background()
	if req.TimeoutMs > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, time.Duration(req.TimeoutMs)*time.Millisecond)
		defer cancel()
		mu.Lock()
		cancelFns[req.CommandID] = cancel
		mu.Unlock()
		defer func() {
			mu.Lock()
			delete(cancelFns, req.CommandID)
			mu.Unlock()
		}()
	}

	cmd := exec.CommandContext(ctx, req.Exec, req.Args...)
	if req.WorkingDir != "" {
		cmd.Dir = req.WorkingDir
	} else {
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

	mu.Lock()
	running[req.CommandID] = cmd
	mu.Unlock()

	start := time.Now()
	err := cmd.Run()
	duration := time.Since(start)

	mu.Lock()
	delete(running, req.CommandID)
	mu.Unlock()

	exitCode := 0
	success := true
	if err != nil {
		success = false
		if exitErr, ok := err.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
		}
	}

	resp := sandbox.AgentExecuteResponse{
		CommandID:  req.CommandID,
		ExitCode:   exitCode,
		Success:    success,
		Stdout:     stdoutBuf.Bytes(),
		Stderr:     stderrBuf.Bytes(),
		DurationMs: duration.Milliseconds(),
	}
	if err != nil {
		resp.Error = err.Error()
	}
	writeJSON(w, resp)
}

func handleCancel(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req sandbox.AgentCancelRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, sandbox.AgentCancelResponse{Success: false})
		return
	}

	mu.Lock()
	cancel, ok := cancelFns[req.CommandID]
	mu.Unlock()

	if ok && cancel != nil {
		cancel()
		writeJSON(w, sandbox.AgentCancelResponse{Success: true})
		return
	}
	writeJSON(w, sandbox.AgentCancelResponse{Success: false})
}

func handleRead(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	data, err := os.ReadFile(path)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Write(data)
}

func handleWrite(w http.ResponseWriter, r *http.Request) {
	var req sandbox.AgentWriteFileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, sandbox.AgentFileResponse{Success: false, Error: err.Error()})
		return
	}
	if err := os.MkdirAll(filepath.Dir(req.Path), 0755); err != nil {
		writeJSON(w, sandbox.AgentFileResponse{Success: false, Error: err.Error()})
		return
	}
	if err := os.WriteFile(req.Path, req.Data, os.FileMode(req.Mode)); err != nil {
		writeJSON(w, sandbox.AgentFileResponse{Success: false, Error: err.Error()})
		return
	}
	writeJSON(w, sandbox.AgentFileResponse{Success: true})
}

func handleList(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	entries, err := os.ReadDir(path)
	if err != nil {
		writeJSON(w, sandbox.AgentListFilesResponse{Success: false, Error: err.Error()})
		return
	}

	var infos []sandbox.AgentFileInfoMsg
	for _, e := range entries {
		fi, err := e.Info()
		if err != nil {
			continue
		}
		infos = append(infos, sandbox.AgentFileInfoMsg{
			Name:        fi.Name(),
			Path:        filepath.Join(path, fi.Name()),
			Size:        fi.Size(),
			Mode:        uint32(fi.Mode()),
			ModTimeUnix: fi.ModTime().Unix(),
			IsDir:       fi.IsDir(),
		})
	}
	writeJSON(w, sandbox.AgentListFilesResponse{Success: true, Entries: infos})
}

func handleDelete(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	if err := os.RemoveAll(path); err != nil {
		writeJSON(w, sandbox.AgentFileResponse{Success: false, Error: err.Error()})
		return
	}
	writeJSON(w, sandbox.AgentFileResponse{Success: true})
}

func handlePort(w http.ResponseWriter, r *http.Request) {
	var req sandbox.AgentPortRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeJSON(w, sandbox.AgentPortResponse{Success: false, Error: err.Error()})
		return
	}
	// Inside the guest we only validate the port; the host owns the actual mapping.
	writeJSON(w, sandbox.AgentPortResponse{
		Success:   true,
		HostPort:  req.ContainerPort,
		PublicURL: fmt.Sprintf("http://localhost:%d", req.ContainerPort),
	})
}

func handleStatus(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	n := len(running)
	mu.Unlock()
	writeJSON(w, sandbox.AgentStatusResponse{
		State:       "running",
		ActiveTasks: int32(n),
		UptimeMs:    0,
	})
}

func writeJSON(w http.ResponseWriter, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(v); err != nil {
		io.WriteString(w, `{"error":"encode failed"}`)
	}
}
