package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	"github.com/mark3labs/mcp-go/server"
	"github.com/narcilee7/S2AA/internal/sandbox"
)

// mcp-server exposes S2AA sandbox capabilities as MCP tools for Claude Desktop,
// Cursor, and other MCP-compatible clients.
func main() {
	backend := os.Getenv("S2AA_BACKEND")
	if backend == "" {
		backend = "microvm"
	}

	cfg := &sandbox.FactoryConfig{IsolationBackend: backend}
	factory, err := sandbox.NewFactory(cfg)
	if err != nil {
		log.Fatalf("Failed to create factory: %v", err)
	}
	defer factory.Close()

	ctx := context.Background()
	sb, err := factory.CreateSandboxWithOptions(sandbox.SandboxOptions{
		Level:        sandbox.LevelIsolated,
		Persistent:   true,
		Capabilities: sandbox.DefaultCapabilities(sandbox.LevelIsolated),
	})
	if err != nil {
		log.Fatalf("Failed to create sandbox: %v", err)
	}
	defer sb.Cleanup()

	// Wait for the microVM to be ready if using microVM backend.
	if backend == "microvm" {
		if _, err := sb.Execute(ctx, sandbox.Command{Exec: "echo", Args: []string{"ready"}}); err != nil {
			log.Fatalf("Sandbox warmup failed: %v", err)
		}
	}

	s := server.NewMCPServer(
		"S2AA Sandbox",
		"0.1.0",
		server.WithToolCapabilities(false),
	)

	// Tool: sandbox_execute
	executeTool := mcp.NewTool("sandbox_execute",
		mcp.WithDescription("Execute a command inside the sandbox"),
		mcp.WithString("exec", mcp.Required(), mcp.Description("Executable path")),
		mcp.WithArray("args", mcp.Description("Arguments"), mcp.Items(map[string]any{"type": "string"})),
		mcp.WithString("working_dir", mcp.Description("Working directory")),
		mcp.WithNumber("timeout_ms", mcp.Description("Timeout in milliseconds"), mcp.DefaultNumber(30000)),
	)
	s.AddTool(executeTool, makeExecuteHandler(sb))

	// Tool: sandbox_read_file
	readTool := mcp.NewTool("sandbox_read_file",
		mcp.WithDescription("Read a file from the sandbox"),
		mcp.WithString("path", mcp.Required(), mcp.Description("File path")),
	)
	s.AddTool(readTool, makeReadFileHandler(sb))

	// Tool: sandbox_write_file
	writeTool := mcp.NewTool("sandbox_write_file",
		mcp.WithDescription("Write a file inside the sandbox"),
		mcp.WithString("path", mcp.Required(), mcp.Description("File path")),
		mcp.WithString("content", mcp.Required(), mcp.Description("File content")),
	)
	s.AddTool(writeTool, makeWriteFileHandler(sb))

	// Tool: sandbox_list_files
	listTool := mcp.NewTool("sandbox_list_files",
		mcp.WithDescription("List files in a sandbox directory"),
		mcp.WithString("path", mcp.Required(), mcp.Description("Directory path")),
	)
	s.AddTool(listTool, makeListFilesHandler(sb))

	// Tool: sandbox_delete_file
	deleteTool := mcp.NewTool("sandbox_delete_file",
		mcp.WithDescription("Delete a file or directory inside the sandbox"),
		mcp.WithString("path", mcp.Required(), mcp.Description("Path to delete")),
	)
	s.AddTool(deleteTool, makeDeleteFileHandler(sb))

	// Tool: sandbox_expose_port
	portTool := mcp.NewTool("sandbox_expose_port",
		mcp.WithDescription("Expose a sandbox port to the host"),
		mcp.WithNumber("port", mcp.Required(), mcp.Description("Container port")),
	)
	s.AddTool(portTool, makeExposePortHandler(sb))

	// Tool: sandbox_snapshot
	snapshotTool := mcp.NewTool("sandbox_snapshot",
		mcp.WithDescription("Create a snapshot of the sandbox state"),
		mcp.WithString("snapshot_id", mcp.Required(), mcp.Description("Snapshot identifier")),
	)
	s.AddTool(snapshotTool, makeSnapshotHandler(sb))

	// Tool: sandbox_restore
	restoreTool := mcp.NewTool("sandbox_restore",
		mcp.WithDescription("Restore the sandbox from a snapshot"),
		mcp.WithString("snapshot_id", mcp.Required(), mcp.Description("Snapshot identifier")),
	)
	s.AddTool(restoreTool, makeRestoreHandler(sb))

	log.Println("S2AA MCP server starting on stdio...")
	if err := server.ServeStdio(s); err != nil {
		log.Fatalf("Server error: %v", err)
	}
}

func makeExecuteHandler(sb sandbox.Sandbox) func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		execPath, _ := req.GetArguments()["exec"].(string)
		if execPath == "" {
			return mcp.NewToolResultError("exec is required"), nil
		}

		var args []string
		if a, ok := req.GetArguments()["args"].([]any); ok {
			for _, v := range a {
				if s, ok := v.(string); ok {
					args = append(args, s)
				}
			}
		}

		workingDir, _ := req.GetArguments()["working_dir"].(string)
		timeoutMs := int64(30000)
		if t, ok := req.GetArguments()["timeout_ms"].(float64); ok {
			timeoutMs = int64(t)
		}

		cmd := sandbox.Command{
			Exec:       execPath,
			Args:       args,
			WorkingDir: workingDir,
			Timeout:    time.Duration(timeoutMs) * time.Millisecond,
		}

		result, err := sb.Execute(ctx, cmd)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("execution failed: %v", err)), nil
		}

		output := fmt.Sprintf("Exit code: %d\nStdout:\n%s\nStderr:\n%s",
			result.ExitCode,
			string(result.Stdout),
			string(result.Stderr),
		)
		return mcp.NewToolResultText(output), nil
	}
}

func makeReadFileHandler(sb sandbox.Sandbox) func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		path, _ := req.GetArguments()["path"].(string)
		if path == "" {
			return mcp.NewToolResultError("path is required"), nil
		}

		data, err := sb.Filesystem().ReadFile(ctx, path)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("read failed: %v", err)), nil
		}
		return mcp.NewToolResultText(string(data)), nil
	}
}

func makeWriteFileHandler(sb sandbox.Sandbox) func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		path, _ := req.GetArguments()["path"].(string)
		content, _ := req.GetArguments()["content"].(string)
		if path == "" {
			return mcp.NewToolResultError("path is required"), nil
		}

		if err := sb.Filesystem().WriteFile(ctx, path, []byte(content), 0644); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("write failed: %v", err)), nil
		}
		return mcp.NewToolResultText("File written successfully"), nil
	}
}

func makeListFilesHandler(sb sandbox.Sandbox) func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		path, _ := req.GetArguments()["path"].(string)
		if path == "" {
			return mcp.NewToolResultError("path is required"), nil
		}

		entries, err := sb.Filesystem().ListFiles(ctx, path)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("list failed: %v", err)), nil
		}

		var output string
		for _, e := range entries {
			output += fmt.Sprintf("%s\t%s\t%d\n", e.Mode.String(), e.Name, e.Size)
		}
		return mcp.NewToolResultText(output), nil
	}
}

func makeDeleteFileHandler(sb sandbox.Sandbox) func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		path, _ := req.GetArguments()["path"].(string)
		if path == "" {
			return mcp.NewToolResultError("path is required"), nil
		}

		if err := sb.Filesystem().DeleteFile(ctx, path); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("delete failed: %v", err)), nil
		}
		return mcp.NewToolResultText("Deleted successfully"), nil
	}
}

func makeExposePortHandler(sb sandbox.Sandbox) func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		portFloat, _ := req.GetArguments()["port"].(float64)
		port := int(portFloat)
		if port == 0 {
			return mcp.NewToolResultError("port is required"), nil
		}

		url, _, err := sb.PortForwarder().ExposePort(ctx, port)
		if err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("expose failed: %v", err)), nil
		}
		return mcp.NewToolResultText(fmt.Sprintf("Exposed at: %s", url)), nil
	}
}

func makeSnapshotHandler(sb sandbox.Sandbox) func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		id, _ := req.GetArguments()["snapshot_id"].(string)
		if id == "" {
			return mcp.NewToolResultError("snapshot_id is required"), nil
		}

		if err := sb.Snapshot(id); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("snapshot failed: %v", err)), nil
		}
		return mcp.NewToolResultText(fmt.Sprintf("Snapshot '%s' created", id)), nil
	}
}

func makeRestoreHandler(sb sandbox.Sandbox) func(context.Context, mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	return func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		id, _ := req.GetArguments()["snapshot_id"].(string)
		if id == "" {
			return mcp.NewToolResultError("snapshot_id is required"), nil
		}

		if err := sb.Restore(id); err != nil {
			return mcp.NewToolResultError(fmt.Sprintf("restore failed: %v", err)), nil
		}
		return mcp.NewToolResultText(fmt.Sprintf("Snapshot '%s' restored", id)), nil
	}
}
