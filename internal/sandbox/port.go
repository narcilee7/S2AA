package sandbox

import "context"

// PortMapping represents an exposed port mapping.
type PortMapping struct {
	ContainerPort int
	HostPort      int
	HostAddr      string
	PublicURL     string
}

// PortForwarder defines port exposure capabilities for a sandbox.
type PortForwarder interface {
	// ExposePort exposes a container port to the host network.
	// Returns a publicly reachable URL and a cleanup function.
	ExposePort(ctx context.Context, containerPort int) (string, func(), error)

	// ListExposedPorts returns all active port mappings.
	ListExposedPorts() []PortMapping
}
