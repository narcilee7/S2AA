package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
)

// build-rootfs automates the creation of a Firecracker rootfs image
// containing the sandbox-agent binary and a minimal Alpine Linux environment.
//
// It tries Docker first (no host root required), then falls back to
// loop-mount + chroot on Linux.
//
// Usage:
//
//	go build -o build-rootfs ./cmd/build-rootfs
//	./build-rootfs -o rootfs.ext4 -size 500M
//
// Prerequisites (Docker path): Docker daemon running.
// Prerequisites (native path): Linux, root privileges, mkfs.ext4, mount, chroot.
func main() {
	output := flag.String("o", "rootfs.ext4", "output ext4 image path")
	size := flag.String("size", "500M", "image size (e.g. 500M, 1G)")
	alpineVer := flag.String("alpine", "v3.19", "alpine branch/version")
	agentBin := flag.String("agent", "sandbox-agent", "path to sandbox-agent binary")
	flag.Parse()

	absOut, err := filepath.Abs(*output)
	if err != nil {
		log.Fatalf("failed to resolve output path: %v", err)
	}
	absAgent, err := filepath.Abs(*agentBin)
	if err != nil {
		log.Fatalf("failed to resolve agent path: %v", err)
	}
	if _, err := os.Stat(absAgent); err != nil {
		log.Fatalf("sandbox-agent binary not found at %s: %v", absAgent, err)
	}

	// Try Docker first.
	if hasDocker() {
		log.Println("Using Docker builder...")
		if err := buildWithDocker(absOut, *size, *alpineVer, absAgent); err != nil {
			log.Fatalf("docker build failed: %v", err)
		}
		return
	}

	log.Println("Docker not available, falling back to native loop-mount builder (requires root)...")
	if os.Getuid() != 0 {
		log.Fatal("native builder requires root privileges. Please run with sudo or install Docker.")
	}
	if err := buildNative(absOut, *size, *alpineVer, absAgent); err != nil {
		log.Fatalf("native build failed: %v", err)
	}
}

func hasDocker() bool {
	cmd := exec.Command("docker", "info")
	return cmd.Run() == nil
}

func buildWithDocker(output, size, alpineVer, agent string) error {
	tmpDir, err := os.MkdirTemp("", "s2aa-rootfs-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

	alpineURL := fmt.Sprintf(
		"https://dl-cdn.alpinelinux.org/alpine/%s/releases/x86_64/alpine-minirootfs-3.19.1-x86_64.tar.gz",
		alpineVer,
	)

	// Download minirootfs.
	if err := runCmd(exec.Command("curl", "-fsSL", "-o", filepath.Join(tmpDir, "alpine.tar.gz"), alpineURL)); err != nil {
		return fmt.Errorf("download alpine: %w", err)
	}

	// Copy agent into temp dir so Docker can access it.
	agentCopy := filepath.Join(tmpDir, "sandbox-agent")
	if err := runCmd(exec.Command("cp", agent, agentCopy)); err != nil {
		return fmt.Errorf("copy agent: %w", err)
	}

	// Write a build script that runs inside the privileged container.
	script := fmt.Sprintf(`set -e
IMG=/output/rootfs.ext4
AGENT=/workspace/sandbox-agent
ALPINE=/workspace/alpine.tar.gz
MNT=/mnt/rootfs

# Create blank image
dd if=/dev/zero of="$IMG" bs=1 count=0 seek=%s
mkfs.ext4 "$IMG"

mkdir -p "$MNT"
mount -o loop "$IMG" "$MNT"

# Extract Alpine
tar -xzf "$ALPINE" -C "$MNT"

# Install ca-certificates
chroot "$MNT" /sbin/apk add --no-cache ca-certificates || true

# Copy agent
mkdir -p "$MNT/usr/local/bin"
cp "$AGENT" "$MNT/usr/local/bin/sandbox-agent"
chmod +x "$MNT/usr/local/bin/sandbox-agent"

# Write init
cat > "$MNT/init" <<'EOF'
#!/bin/sh
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mount -t tmpfs tmpfs /dev/shm
mkdir -p /workspace
mkdir -p /run
exec /usr/local/bin/sandbox-agent
EOF
chmod +x "$MNT/init"

umount "$MNT"
`, size)

	scriptPath := filepath.Join(tmpDir, "build.sh")
	if err := os.WriteFile(scriptPath, []byte(script), 0755); err != nil {
		return err
	}

	// Run privileged Alpine container to do the build.
	cmd := exec.Command("docker", "run", "--rm", "--privileged",
		"-v", tmpDir+":/workspace",
		"-v", filepath.Dir(output)+":/output",
		"alpine:"+alpineVer,
		"sh", "/workspace/build.sh",
	)
	return runCmd(cmd)
}

func buildNative(output, size, alpineVer, agent string) error {
	tmpDir, err := os.MkdirTemp("", "s2aa-rootfs-*")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmpDir)

	alpineURL := fmt.Sprintf(
		"https://dl-cdn.alpinelinux.org/alpine/%s/releases/x86_64/alpine-minirootfs-3.19.1-x86_64.tar.gz",
		alpineVer,
	)
	alpineTar := filepath.Join(tmpDir, "alpine.tar.gz")
	if err := runCmd(exec.Command("curl", "-fsSL", "-o", alpineTar, alpineURL)); err != nil {
		return fmt.Errorf("download alpine: %w", err)
	}

	if err := runCmd(exec.Command("dd", "if=/dev/zero", "of="+output, "bs=1", "count=0", "seek="+size)); err != nil {
		return fmt.Errorf("create image: %w", err)
	}
	if err := runCmd(exec.Command("mkfs.ext4", output)); err != nil {
		return fmt.Errorf("mkfs.ext4: %w", err)
	}

	mnt := filepath.Join(tmpDir, "mnt")
	os.MkdirAll(mnt, 0755)
	if err := runCmd(exec.Command("mount", "-o", "loop", output, mnt)); err != nil {
		return fmt.Errorf("mount: %w", err)
	}
	defer runCmd(exec.Command("umount", mnt))

	if err := runCmd(exec.Command("tar", "-xzf", alpineTar, "-C", mnt)); err != nil {
		return fmt.Errorf("extract alpine: %w", err)
	}

	// Install ca-certificates
	_ = runCmd(exec.Command("chroot", mnt, "/sbin/apk", "add", "--no-cache", "ca-certificates"))

	agentDst := filepath.Join(mnt, "usr", "local", "bin", "sandbox-agent")
	os.MkdirAll(filepath.Dir(agentDst), 0755)
	if err := runCmd(exec.Command("cp", agent, agentDst)); err != nil {
		return fmt.Errorf("copy agent: %w", err)
	}
	_ = os.Chmod(agentDst, 0755)

	initScript := `#!/bin/sh
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev
mount -t tmpfs tmpfs /dev/shm
mkdir -p /workspace
mkdir -p /run
exec /usr/local/bin/sandbox-agent
`
	initPath := filepath.Join(mnt, "init")
	if err := os.WriteFile(initPath, []byte(initScript), 0755); err != nil {
		return err
	}

	return nil
}

func runCmd(cmd *exec.Cmd) error {
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s: %w\n%s", cmd.String(), err, out.String())
	}
	return nil
}
