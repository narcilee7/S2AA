# agent-sandbox

一个面向 AI Agent 的生产级安全沙箱执行环境，采用 **Firecracker microVM + Guest Agent** 架构，支持硬件级隔离、持久化 Workspace、流式执行、文件系统 API、端口映射、网络代理与审计日志。

[![Go Version](https://img.shields.io/badge/Go-1.25.5-blue)](https://go.dev)

---

## 核心特性

- **4 级渐进安全隔离**：Trusted → Restricted → Isolated → Secure
- **Firecracker microVM 硬件隔离**：L3/L4 可选择基于 AWS Firecracker 的独立内核隔离（替代共享内核的 Docker）
- **统一沙箱接口**：`Execute` / `ExecuteStreaming` / `Cancel` / `Filesystem` / `PortForwarder` / `Snapshot` / `Restore`
- **持久化 Workspace**：支持长期运行的 Agent 环境，状态跨会话保留
- **文件系统 API**：Agent 可直接读写文件，无需通过 shell 命令中转
- **端口映射/服务预览**：沙箱内启动的服务可动态暴露给外部访问
- **网络代理与审计**：默认拒绝出站，按域名/IP/端口白名单放行；所有网络请求写入审计日志
- **Checkpoint/Restore**：基于 Firecracker Snapshot API，支持毫秒级暂停与恢复

---

## 架构概览

```
┌─────────────────────────────────────────────────────────────┐
│                        Host (你的服务器)                      │
│  ┌──────────────┐   vsock   ┌─────────────────────────────┐ │
│  │   Factory    │◄─────────►│  Firecracker microVM (L3)   │ │
│  │  (host side) │           │  ┌───────────────────────┐  │ │
│  └──────────────┘           │  │   sandbox-agent       │  │ │
│         │                   │  │  (guest side HTTP API)│  │ │
│         ▼                   │  │  ├─ Execute command   │  │ │
│  ┌──────────────┐           │  │  ├─ Read/Write files  │  │ │
│  │ Network Proxy│           │  │  ├─ Port forwarding   │  │ │
│  │  (egress)    │           │  │  └─ Health/Status     │  │ │
│  └──────────────┘           │  └───────────────────────┘  │ │
│         │                   └─────────────────────────────┘ │
│         ▼                                                   │
│  ┌──────────────┐                                           │
│  │ Audit Logger │                                           │
│  │ (JSON Lines) │                                           │
│  └──────────────┘                                           │
└─────────────────────────────────────────────────────────────┘
```

### 隔离技术选择

| 后端 | 说明 | 适用场景 |
|:---|:---|:---|
| `legacy` | L1 `os/exec` + L2 `cgroup/rlimit` + L3 Docker + L4 gRPC client | 兼容旧代码，开发测试 |
| `microvm` | L3/L4 统一使用 Firecracker microVM + vsock guest agent | 生产环境，执行不可信代码 |

通过 `FactoryConfig.IsolationBackend` 切换，无需改动业务代码。

---

## 安装

```bash
go get github.com/narcilee7/S2AA
```

运行 Firecracker 后端需要预先安装：
- [Firecracker](https://github.com/firecracker-microvm/firecracker) 二进制
- Linux 内核镜像（`vmlinux`）
- 包含 `sandbox-agent` 的根文件系统（rootfs）

```bash
export FIRECRACKER_KERNEL=/opt/firecracker/vmlinux
export FIRECRACKER_ROOTFS=/opt/firecracker/rootfs.ext4
```

---

## 快速开始

### 基础命令执行

```go
package main

import (
    "context"
    "fmt"
    "log"

    "github.com/narcilee7/S2AA/internal/sandbox"
)

func main() {
    // 使用 microVM 后端
    cfg := &sandbox.FactoryConfig{IsolationBackend: "microvm"}
    f, err := sandbox.NewFactory(cfg)
    if err != nil {
        log.Fatal(err)
    }
    defer f.Close()

    ctx := context.Background()
    cmd := sandbox.NewCommand("echo", "hello, sandbox")

    result, err := f.ExecuteCommand(ctx, sandbox.LevelIsolated, *cmd)
    if err != nil {
        log.Fatal(err)
    }

    fmt.Printf("exit=%d stdout=%s", result.ExitCode, string(result.Stdout))
}
```

### 持久化 Workspace

```go
sb, err := f.CreateSandboxWithOptions(sandbox.SandboxOptions{
    Level:        sandbox.LevelIsolated,
    Persistent:   true,
})
if err != nil {
    log.Fatal(err)
}
// 多次读写文件，状态保留
fs := sb.Filesystem()
fs.WriteFile(ctx, "data.json", []byte(`{"counter":1}`), 0644)

// 之后通过 ResumeSandbox 重新获取
resumed, _ := f.ResumeSandbox(sb.Info().ID)
data, _ := resumed.Filesystem().ReadFile(ctx, "data.json")
```

### 文件系统 API

```go
fs := sb.Filesystem()
fs.WriteFile(ctx, "/workspace/main.py", []byte(code), 0644)
fs.UploadFile(ctx, "/host/requirements.txt", "/workspace/requirements.txt")
entries, _ := fs.ListFiles(ctx, "/workspace")
```

### 端口映射

```go
pf := sb.PortForwarder()
url, cleanup, err := pf.ExposePort(ctx, 8080)
if err != nil {
    log.Fatal(err)
}
defer cleanup()
fmt.Println("Service reachable at:", url)
```

### Snapshot / Restore

```go
if err := sb.Snapshot("checkpoint-1"); err != nil {
    log.Fatal(err)
}
// ... 运行一些可能破坏环境的操作 ...
if err := sb.Restore("checkpoint-1"); err != nil {
    log.Fatal(err)
}
```

---

## 4 级安全模型

| 级别 | 名称 | 隔离方式 | 说明 |
|:--:|:---|:---|:---|
| **L1** | `LevelTrusted` | `os/exec` | 完全信任，无限制，本地脚本 |
| **L2** | `LevelRestricted` | `cgroup/rlimit/seccomp` | 进程级限制，syscall 过滤 |
| **L3** | `LevelIsolated` | **Firecracker microVM** (默认) 或 Docker | 硬件级隔离，独立内核 |
| **L4** | `LevelSecure` | **Firecracker microVM** (默认) 或远程 gRPC | 远程/物理隔离 |

> 当 `IsolationBackend = "microvm"` 时，L3 和 L4 均使用 Firecracker microVM，区别仅在于资源配额和网络策略的严格程度。

---

## 网络代理与审计

每个 microVM 沙箱启动时会自动在 host 端启动一个 **HTTP/HTTPS CONNECT 代理**，并通过环境变量注入到 guest 的所有命令执行中。

- **默认策略**：`NetworkBlockAll`（完全拒绝出站）
- **白名单**：按域名、IP/CIDR、端口放行
- **审计日志**：所有被拦截/放行的连接记录到 `audit.Auditor`

```go
caps := &sandbox.Capabilities{
    NetworkAccess:  sandbox.NetworkWhitelist,
    AllowedDomains: []string{"api.openai.com", "github.com"},
    AllowedPorts:   []int{443},
}

sb, _ := f.CreateSandboxWithOptions(sandbox.SandboxOptions{
    Level:        sandbox.LevelIsolated,
    Capabilities: caps,
})
```

---

## 项目结构

```
agent-sandbox/
├── api/
│   └── sandbox.proto               # Guest agent gRPC 规范（当前手写 JSON-over-HTTP 实现）
├── cmd/
│   └── sandbox-agent/
│       └── main.go                 # 运行在 microVM guest 内的 agent
├── internal/
│   ├── audit/
│   │   └── audit.go                # 审计日志接口
│   ├── network/
│   │   └── proxy.go                # HTTP/HTTPS CONNECT 代理 + 策略检查
│   ├── sandbox/
│   │   ├── sandbox.go              # 核心接口定义
│   │   ├── type.go                 # 类型与默认值
│   │   ├── factory.go              # Factory 与生命周期管理
│   │   ├── trusted.go              # L1 (legacy)
│   │   ├── restricted.go           # L2 (legacy)
│   │   ├── isolated.go             # L3 Docker (legacy)
│   │   ├── secure.go               # L4 gRPC client (legacy)
│   │   ├── microvm.go              # L3/L4 Firecracker host 端封装
│   │   ├── microvm_agent.go        # Host vsock HTTP 客户端
│   │   ├── microvm_proto.go        # Guest agent 通信协议结构体
│   │   ├── fs.go                   # Filesystem 接口
│   │   ├── port.go                 # PortForwarder 接口
│   │   └── legacy.go               # Legacy sandbox 的兼容实现
│   └── utils/
│       └── common.go               # 通用工具
├── go.mod / go.sum
└── README.md
```

---

## 运行测试

```bash
go test ./...
```

测试覆盖了：
- 4 级沙箱创建与销毁
- 命令执行、超时、并发、流式输出
- 文件系统 API 读写列删
- 持久化 Workspace 与 Resume
- Snapshot/Restore 接口可用性
- 网络代理白名单策略

---

## Roadmap

- [x] 统一 `Sandbox` 接口扩展（Filesystem / PortForwarder / Snapshot / Restore）
- [x] Firecracker microVM 集成骨架（host + guest agent + vsock）
- [x] 持久化 Workspace 与 Factory 管理
- [x] 网络代理 + 审计日志骨架
- [x] Checkpoint/Restore 基于 Firecracker Snapshot API
- [ ] Protobuf 代码生成替代手写 JSON 协议
- [ ] Guest agent 流式执行（WebSocket / gRPC streaming）
- [ ] Secret 动态注入（避免环境变量泄漏长生命周期凭证）
- [ ] MCP (Model Context Protocol) Server 适配
- [ ] 容器镜像构建工具（自动化 rootfs 打包）

---

## 许可证

MIT
