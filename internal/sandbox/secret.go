package sandbox

import (
	"context"
	"fmt"
	"os"
)

// SecretProvider resolves secret values by key at execution time.
type SecretProvider interface {
	GetSecret(ctx context.Context, key string) (string, error)
}

// MapSecretProvider resolves secrets from an in-memory map.
type MapSecretProvider struct {
	secrets map[string]string
}

// NewMapSecretProvider creates a secret provider backed by a map.
func NewMapSecretProvider(secrets map[string]string) *MapSecretProvider {
	copy := make(map[string]string, len(secrets))
	for k, v := range secrets {
		copy[k] = v
	}
	return &MapSecretProvider{secrets: copy}
}

// GetSecret returns the secret value for the given key.
func (m *MapSecretProvider) GetSecret(ctx context.Context, key string) (string, error) {
	v, ok := m.secrets[key]
	if !ok {
		return "", fmt.Errorf("secret not found: %s", key)
	}
	return v, nil
}

// EnvSecretProvider resolves secrets from host environment variables.
// The secret key "FOO" is looked up as "S2AA_SECRET_FOO" in the host env.
type EnvSecretProvider struct {
	prefix string
}

// NewEnvSecretProvider creates a secret provider backed by environment variables.
func NewEnvSecretProvider(prefix string) *EnvSecretProvider {
	if prefix == "" {
		prefix = "S2AA_SECRET_"
	}
	return &EnvSecretProvider{prefix: prefix}
}

// GetSecret returns the secret value from the host environment.
func (e *EnvSecretProvider) GetSecret(ctx context.Context, key string) (string, error) {
	v := os.Getenv(e.prefix + key)
	if v == "" {
		return "", fmt.Errorf("secret not found in env: %s%s", e.prefix, key)
	}
	return v, nil
}
