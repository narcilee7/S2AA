package audit

import (
	"time"
)

// ExecutionRecord captures a command execution event.
type ExecutionRecord struct {
	SandboxID   string
	CommandID   string
	Exec        string
	Args        []string
	ExitCode    int
	Success     bool
	ErrorMsg    string
	Duration    time.Duration
	CPUUsage    float64
	MemoryBytes int64
	Timestamp   time.Time
}

// NetworkConn captures an outbound network connection attempt.
type NetworkConn struct {
	SandboxID string
	Protocol  string
	Host      string
	IP        string
	Port      int
	Allowed   bool
	Bytes     int64
	Timestamp time.Time
}

// FileOp captures a filesystem operation.
type FileOp struct {
	SandboxID string
	Operation string // read, write, delete, list
	Path      string
	Allowed   bool
	Timestamp time.Time
}

// SyscallEvent captures a system call observation.
type SyscallEvent struct {
	SandboxID string
	Name      string
	Allowed   bool
	Timestamp time.Time
}

// Auditor defines the interface for sandbox audit logging.
type Auditor interface {
	LogExecution(record ExecutionRecord)
	LogNetwork(conn NetworkConn)
	LogFileAccess(op FileOp)
	LogSyscall(event SyscallEvent)
}

// NoOpAuditor discards all audit events.
type NoOpAuditor struct{}

func (n *NoOpAuditor) LogExecution(record ExecutionRecord) {}
func (n *NoOpAuditor) LogNetwork(conn NetworkConn)         {}
func (n *NoOpAuditor) LogFileAccess(op FileOp)             {}
func (n *NoOpAuditor) LogSyscall(event SyscallEvent)       {}

// DefaultNoOp returns a no-op auditor.
func DefaultNoOp() Auditor {
	return &NoOpAuditor{}
}
