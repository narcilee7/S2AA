package sandbox

import "time"

// The following structs mirror api/sandbox.proto for communication
// between the host and the microVM guest agent over vsock (JSON-over-HTTP).
// They will be replaced by generated protobuf code in a later iteration.

type AgentExecuteRequest struct {
	CommandID  string   `json:"command_id"`
	Exec       string   `json:"exec"`
	Args       []string `json:"args"`
	Env        []string `json:"env"`
	WorkingDir string   `json:"working_dir"`
	Stdin      []byte   `json:"stdin"`
	TimeoutMs  int64    `json:"timeout_ms"`
}

type AgentExecuteResponse struct {
	CommandID  string `json:"command_id"`
	ExitCode   int    `json:"exit_code"`
	Success    bool   `json:"success"`
	Stdout     []byte `json:"stdout"`
	Stderr     []byte `json:"stderr"`
	Error      string `json:"error"`
	DurationMs int64  `json:"duration_ms"`
}

type AgentStreamChunk struct {
	Stdout   []byte             `json:"stdout,omitempty"`
	Stderr   []byte             `json:"stderr,omitempty"`
	Progress float64            `json:"progress,omitempty"`
	Result   *AgentExecuteResponse `json:"result,omitempty"`
}

type AgentCancelRequest struct {
	CommandID string `json:"command_id"`
}

type AgentCancelResponse struct {
	Success bool `json:"success"`
}

type AgentFileRequest struct {
	Path string `json:"path"`
}

type AgentWriteFileRequest struct {
	Path string `json:"path"`
	Data []byte `json:"data"`
	Mode uint32 `json:"mode"`
}

type AgentFileResponse struct {
	Success bool   `json:"success"`
	Error   string `json:"error,omitempty"`
}

type AgentFileInfoMsg struct {
	Name        string    `json:"name"`
	Path        string    `json:"path"`
	Size        int64     `json:"size"`
	Mode        uint32    `json:"mode"`
	ModTimeUnix int64     `json:"mod_time_unix"`
	IsDir       bool      `json:"is_dir"`
}

func (m AgentFileInfoMsg) ModTime() time.Time {
	return time.Unix(m.ModTimeUnix, 0)
}

type AgentListFilesResponse struct {
	Success bool               `json:"success"`
	Error   string             `json:"error,omitempty"`
	Entries []AgentFileInfoMsg `json:"entries"`
}

type AgentPortRequest struct {
	ContainerPort int32 `json:"container_port"`
}

type AgentPortResponse struct {
	Success   bool   `json:"success"`
	Error     string `json:"error,omitempty"`
	HostPort  int32  `json:"host_port"`
	PublicURL string `json:"public_url"`
}

type AgentStatusRequest struct {
	SandboxID string `json:"sandbox_id"`
}

type AgentStatusResponse struct {
	State       string `json:"state"`
	ActiveTasks int32  `json:"active_tasks"`
	UptimeMs    int64  `json:"uptime_ms"`
}
