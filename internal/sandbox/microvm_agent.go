package sandbox

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/mdlayher/vsock"
	"github.com/narcilee7/S2AA/api/sandboxpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// agentClient communicates with the sandbox-agent running inside a microVM via gRPC over vsock.
type agentClient struct {
	client sandboxpb.SandboxServiceClient
	conn   *grpc.ClientConn
}

// close closes the underlying gRPC connection.
func (c *agentClient) close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// newAgentClientVSOCK creates a gRPC client that dials the guest via AF_VSOCK.
func newAgentClientVSOCK(guestCID uint32, guestPort uint32) (*agentClient, error) {
	target := fmt.Sprintf("vsock-%d-%d", guestCID, guestPort)
	conn, err := grpc.NewClient("passthrough:///"+target,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
		grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
			return vsock.Dial(guestCID, guestPort, nil)
		}),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to create grpc client: %w", err)
	}
	return &agentClient{
		client: sandboxpb.NewSandboxServiceClient(conn),
		conn:   conn,
	}, nil
}

// newAgentClientTCP creates a gRPC client for local testing via TCP forwarding.
func newAgentClientTCP(host string) (*agentClient, error) {
	conn, err := grpc.NewClient(host, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, fmt.Errorf("failed to create grpc client: %w", err)
	}
	return &agentClient{
		client: sandboxpb.NewSandboxServiceClient(conn),
		conn:   conn,
	}, nil
}

func (c *agentClient) Execute(ctx context.Context, req *sandboxpb.ExecuteRequest) (*sandboxpb.ExecuteResponse, error) {
	return c.client.Execute(ctx, req)
}

func (c *agentClient) ExecuteStream(ctx context.Context, req *sandboxpb.ExecuteRequest) (grpc.ServerStreamingClient[sandboxpb.StreamChunk], error) {
	return c.client.ExecuteStream(ctx, req)
}

func (c *agentClient) Cancel(ctx context.Context, req *sandboxpb.CancelRequest) (*sandboxpb.CancelResponse, error) {
	return c.client.Cancel(ctx, req)
}

func (c *agentClient) ReadFile(ctx context.Context, path string) (*sandboxpb.ReadFileResponse, error) {
	return c.client.ReadFile(ctx, &sandboxpb.FileRequest{Path: path})
}

func (c *agentClient) WriteFile(ctx context.Context, path string, data []byte, mode uint32) (*sandboxpb.FileResponse, error) {
	return c.client.WriteFile(ctx, &sandboxpb.WriteFileRequest{Path: path, Data: data, Mode: mode})
}

func (c *agentClient) ListFiles(ctx context.Context, path string) (*sandboxpb.ListFilesResponse, error) {
	return c.client.ListFiles(ctx, &sandboxpb.FileRequest{Path: path})
}

func (c *agentClient) DeleteFile(ctx context.Context, path string) (*sandboxpb.FileResponse, error) {
	return c.client.DeleteFile(ctx, &sandboxpb.FileRequest{Path: path})
}

func (c *agentClient) MkdirAll(ctx context.Context, path string, mode uint32) (*sandboxpb.FileResponse, error) {
	return c.client.MkdirAll(ctx, &sandboxpb.MkdirRequest{Path: path, Mode: mode})
}

func (c *agentClient) Stat(ctx context.Context, path string) (*sandboxpb.StatResponse, error) {
	return c.client.Stat(ctx, &sandboxpb.FileRequest{Path: path})
}

func (c *agentClient) ExposePort(ctx context.Context, port int32) (*sandboxpb.PortResponse, error) {
	return c.client.ExposePort(ctx, &sandboxpb.PortRequest{ContainerPort: port})
}

func (c *agentClient) Status(ctx context.Context) (*sandboxpb.StatusResponse, error) {
	return c.client.GetStatus(ctx, &sandboxpb.StatusRequest{})
}

func (c *agentClient) Health(ctx context.Context) error {
	// Use GetStatus as a lightweight health check.
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	_, err := c.client.GetStatus(ctx, &sandboxpb.StatusRequest{})
	return err
}
