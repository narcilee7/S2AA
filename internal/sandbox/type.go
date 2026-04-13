package sandbox

import (
	"fmt"
	"math"
	"time"
)

// SecurityLevel defines security level of a sandbox.
type SecurityLevel int

const (
	// LevelTrusted: L1 - Fully trusted execution, no restrictions
	LevelTrusted SecurityLevel = iota + 1
	// LevelRestricted: L2 - Process-level restrictions, syscall filtering
	LevelRestricted
	// LevelIsolated: L3 - Container isolation
	LevelIsolated
	// LevelSecure: L4 - Remote sandbox, physical isolation
	LevelSecure
)

// String returns string representation of security level.
func (l SecurityLevel) String() string {
	switch l {
	case LevelTrusted:
		return "trusted"
	case LevelRestricted:
		return "restricted"
	case LevelIsolated:
		return "isolated"
	case LevelSecure:
		return "secure"
	default:
		return "unknown"
	}
}

// CommandType defines type of command to execute.
type CommandType string

const (
	// CommandShell: Shell command execution
	CommandShell CommandType = "shell"
	// CommandCode: Code generation/execution
	CommandCode CommandType = "code"
	// CommandFile: File operations
	CommandFile CommandType = "file"
	// CommandNetwork: Network requests
	CommandNetwork CommandType = "network"
	// CommandCustom: Custom command
	CommandCustom CommandType = "custom"
)

// Command represents an execution command.
type Command struct {
	// Basic fields
	ID   string      // Command unique ID
	Type CommandType // Command type

	// Execution parameters
	Exec       string   // Executable path
	Args       []string // Arguments
	Env        []string // Environment variables
	WorkingDir string   // Working directory

	// I/O
	Stdin  []byte // Standard input (content)
	Stdout []byte // Standard output (buffered result)
	Stderr []byte // Standard error (buffered result)

	// Timeout control
	Timeout time.Duration // Execution timeout

	// Secrets
	Secrets []string // Secret keys to inject dynamically via SecretProvider

	// Metadata
	Metadata map[string]string
}

// NewCommand creates a new command with defaults.
func NewCommand(exec string, args ...string) *Command {
	return &Command{
		Exec:     exec,
		Args:     args,
		Env:      make([]string, 0),
		Metadata: make(map[string]string),
		Timeout:  5 * time.Minute,
	}
}

// Result represents result of command execution.
type Result struct {
	CommandID string // Associated command ID

	// Execution status
	ExitCode int   // Exit code
	Success  bool  // Success status
	Error    error // Execution error

	// Output
	Stdout []byte // Standard output
	Stderr []byte // Standard error

	// Performance metrics
	Duration time.Duration // Execution duration
	Metrics  *ExecutionMetrics

	// Sandbox info
	SandboxID     string // Used sandbox ID
	SecurityLevel SecurityLevel
}

// ExecutionMetrics contains execution metrics.
type ExecutionMetrics struct {
	// Resource usage
	CPUUsage        float64 // CPU usage (0-1)
	MemoryBytes     int64   // Memory peak (bytes)
	CPUMilliseconds int64   // CPU time (ms)

	// I/O statistics
	DiskReadBytes  int64 // Disk read
	DiskWriteBytes int64 // Disk write
	DiskIOPs       int64 // I/O operations
	NetworkBytes   int64 // Network traffic

	// Syscall tracing (L2+)
	Syscalls []SyscallInfo

	// Container info (L3+)
	ContainerID string // Container ID
	ImageName   string // Used image name
}

// SyscallInfo contains system call information.
type SyscallInfo struct {
	Name        string
	Timestamp   time.Time
	Duration    time.Duration
	Args        []string
	ReturnValue int
}

// SandboxInfo contains sandbox information.
type SandboxInfo struct {
	ID            string
	Level         SecurityLevel
	State         string
	WorkspaceDir  string
	Persistent    bool
	pid           int // Container/process ID
	CreatedAt     time.Time
	ActiveTasks   int // Active tasks count
	ResourceUsage *ResourceUsage
}

// ResourceUsage contains resource usage statistics.
type ResourceUsage struct {
	CPUUsage     float64
	MemoryBytes  int64
	DiskBytes    int64
	NetworkBytes int64
}

// ResourceLimits defines resource limits for a sandbox.
type ResourceLimits struct {
	// CPU limits
	CPUMax     float64 // Max CPU cores
	CPUPercent float64 // CPU percentage limit (0-1)
	CPUQuota   int64   // CPU quota (ms)

	// Memory limits
	MemoryBytes int64 // Memory limit (bytes)
	MemorySwap  int64 // Swap limit (bytes)

	// Disk limits
	DiskQuotaBytes int64 // Disk quota
	DiskIORate     int64 // Disk I/O rate (bytes/s)

	// Network limits
	NetworkRate int64 // Network bandwidth (bytes/s)

	// Process limits
	MaxProcesses  int // Max processes
	MaxThreads    int // Max threads
	MaxFiles      int // Max file descriptors
	MaxConcurrent int // Max concurrent executions

	// Execution timeout
	Timeout time.Duration // Execution timeout
}

// DefaultResourceLimits returns default resource limits for a security level.
func DefaultResourceLimits(level SecurityLevel) *ResourceLimits {
	switch level {
	case LevelTrusted:
		return &ResourceLimits{
			CPUMax:       math.MaxFloat64,
			MemoryBytes:  math.MaxInt64,
			MaxProcesses: math.MaxInt32,
			MaxFiles:     math.MaxInt32,
			Timeout:      30 * time.Minute,
		}
	case LevelRestricted:
		return &ResourceLimits{
			CPUMax:       2,
			CPUPercent:   1.0,
			MemoryBytes:  512 * 1024 * 1024, // 512MB
			MaxProcesses: 100,
			MaxFiles:     1024,
			Timeout:      5 * time.Minute,
		}
	case LevelIsolated:
		return &ResourceLimits{
			CPUMax:       1,
			CPUPercent:   0.8,
			MemoryBytes:  256 * 1024 * 1024, // 256MB
			MaxProcesses: 50,
			MaxFiles:     512,
			Timeout:      3 * time.Minute,
		}
	case LevelSecure:
		return &ResourceLimits{
			CPUMax:       0.5,
			CPUPercent:   0.5,
			MemoryBytes:  128 * 1024 * 1024, // 128MB
			MaxProcesses: 10,
			MaxFiles:     256,
			Timeout:      1 * time.Minute,
		}
	default:
		return DefaultResourceLimits(LevelTrusted)
	}
}

// Validate validates resource limits.
func (r *ResourceLimits) Validate() error {
	if r.CPUMax <= 0 {
		return fmt.Errorf("CPU max must be positive")
	}
	if r.MemoryBytes <= 0 {
		return fmt.Errorf("memory bytes must be positive")
	}
	if r.MaxProcesses < 0 {
		return fmt.Errorf("max processes cannot be negative")
	}
	if r.MaxFiles < 0 {
		return fmt.Errorf("max files cannot be negative")
	}
	return nil
}

// NetworkPolicy defines network access policy.
type NetworkPolicy int

const (
	// NetworkAllowAll: Allow all network access
	NetworkAllowAll NetworkPolicy = iota + 1
	// NetworkBlockAll: Block all network access
	NetworkBlockAll
	// NetworkWhitelist: Whitelist mode
	NetworkWhitelist
	// NetworkBlacklist: Blacklist mode
	NetworkBlacklist
	// NetworkLocalOnly: Allow local access only
	NetworkLocalOnly
)

// String returns string representation of network policy.
func (p NetworkPolicy) String() string {
	switch p {
	case NetworkAllowAll:
		return "allow-all"
	case NetworkBlockAll:
		return "block-all"
	case NetworkWhitelist:
		return "whitelist"
	case NetworkBlacklist:
		return "blacklist"
	case NetworkLocalOnly:
		return "local-only"
	default:
		return "unknown"
	}
}

// Capabilities defines capability boundaries for a sandbox.
type Capabilities struct {
	// Syscall control
	AllowedSyscalls []string // Allowed syscalls (whitelist mode)
	BlockedSyscalls []string // Blocked syscalls (blacklist mode)

	// Filesystem access
	ReadPaths   []string // Allowed read paths (glob patterns)
	WritePaths  []string // Allowed write paths (glob patterns)
	CreatePaths []string // Allowed create paths (glob patterns)

	// Network access policy
	NetworkAccess  NetworkPolicy
	AllowedDomains []string // Allowed domains
	BlockedDomains []string // Blocked domains
	AllowedIPs     []string // Allowed IPs/CIDR
	AllowedPorts   []int    // Allowed ports

	// Execution permissions
	AllowedExecs []string // Allowed executables
	BlockedExecs []string // Blocked executables

	// Environment variables
	AllowedEnv []string // Allowed environment variables
}

// DefaultCapabilities returns default capabilities for a security level.
func DefaultCapabilities(level SecurityLevel) *Capabilities {
	switch level {
	case LevelTrusted:
		return &Capabilities{
			NetworkAccess: NetworkAllowAll,
		}
	case LevelRestricted:
		return &Capabilities{
			AllowedSyscalls: []string{
				"read", "write", "open", "openat", "close",
				"stat", "fstat", "lstat",
				"mmap", "munmap", "mprotect",
				"exit", "exit_group",
				"getpid", "getppid",
				"gettimeofday", "clock_gettime", "clock_nanosleep",
				"brk", "madvise",
				"rt_sigreturn", "sigreturn",
			},
			BlockedSyscalls: []string{
				"execve", "fork", "clone", "clone3",
				"mount", "umount", "umount2",
				"ptrace", "kexec_load",
				"swapon", "swapoff",
				"reboot", "sethostname",
				"chroot", "pivot_root",
			},
			ReadPaths:     []string{"/tmp/**", "/var/tmp/**"},
			WritePaths:    []string{"/tmp/**", "/var/tmp/**"},
			NetworkAccess: NetworkLocalOnly,
		}
	case LevelIsolated:
		return &Capabilities{
			AllowedSyscalls: []string{
				"read", "write", "exit", "exit_group",
			},
			NetworkAccess: NetworkBlockAll,
		}
	case LevelSecure:
		return &Capabilities{
			AllowedSyscalls: []string{
				"read", "write", "exit",
			},
			NetworkAccess: NetworkBlockAll,
		}
	default:
		return DefaultCapabilities(LevelTrusted)
	}
}
