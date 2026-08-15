// Package dockerrun re-launches pelfs inside a Linux container when the host
// cannot mount FUSE directly (e.g. macOS without macFUSE). The subshell then
// runs inside the container with the PelicanFS mounted there.
package dockerrun

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// DefaultImage is a small image with a shell and CA certificates; the pelfs
// linux binary is bind-mounted into it, so no image build is required.
const DefaultImage = "alpine:3.21"

// Options for the containerized run.
type Options struct {
	PrefixURL      string
	TokenPath      string   // host path of bearer token file ("" = none found)
	EncryptKeyPath string   // host path of the encryption private key ("" = none)
	StatsPath      string   // host path for the stats file ("" = none); its directory is mounted rw
	Image          string   // container image; DefaultImage if empty
	ExtraArgs      []string // pelfs shell flags forwarded into the container
}

// Available reports whether the docker CLI is usable.
func Available() bool {
	docker, err := exec.LookPath("docker")
	if err != nil {
		return false
	}
	return exec.Command(docker, "info").Run() == nil
}

// findLinuxBinary locates a pelfs binary built for linux/<hostarch>:
// $PELFS_LINUX_BINARY, or pelfs-linux-<arch> next to the running executable.
func findLinuxBinary() (string, error) {
	if p := os.Getenv("PELFS_LINUX_BINARY"); p != "" {
		if _, err := os.Stat(p); err != nil {
			return "", fmt.Errorf("$PELFS_LINUX_BINARY=%s: %w", p, err)
		}
		return p, nil
	}
	exe, err := os.Executable()
	if err != nil {
		return "", err
	}
	exe, _ = filepath.EvalSymlinks(exe)
	cand := filepath.Join(filepath.Dir(exe), "pelfs-linux-"+runtime.GOARCH)
	if _, err := os.Stat(cand); err == nil {
		return cand, nil
	}
	return "", fmt.Errorf("no Linux pelfs binary found: build one with `make linux` (looked for %s and $PELFS_LINUX_BINARY)", cand)
}

// Run executes `pelfs shell` inside a container with /dev/fuse available,
// inheriting this process's terminal. It returns the container's exit code.
func Run(opts Options) (int, error) {
	docker, err := exec.LookPath("docker")
	if err != nil {
		return 1, fmt.Errorf("macFUSE is not installed and docker is not on PATH; install macFUSE (https://macfuse.github.io) or Docker")
	}
	bin, err := findLinuxBinary()
	if err != nil {
		return 1, err
	}
	image := opts.Image
	if image == "" {
		image = DefaultImage
	}

	args := []string{
		"run", "--rm",
		"--device", "/dev/fuse",
		"--cap-add", "SYS_ADMIN",
		// JuiceFS renices itself to -19 for FUSE latency; without this cap
		// the setpriority call fails with a per-mount warning.
		"--cap-add", "SYS_NICE",
		"--security-opt", "apparmor=unconfined",
		// Docker Desktop provides host.docker.internal natively; on Linux
		// engines it needs the host-gateway alias (harmless elsewhere).
		"--add-host", "host.docker.internal:host-gateway",
		"-v", bin + ":/usr/local/bin/pelfs:ro",
		"-e", "PELFS_IN_DOCKER=1",
		"--hostname", "pelfs",
	}
	if isTerminal() {
		args = append(args, "-it")
	} else {
		args = append(args, "-i")
	}
	if opts.TokenPath != "" {
		args = append(args,
			"-v", opts.TokenPath+":/run/pelfs/token:ro",
			"-e", "BEARER_TOKEN_FILE=/run/pelfs/token")
	}
	// Share the host's Pelican client config base — which holds the
	// credential wallet at <base>/credentials/client-credentials.pem —
	// so the client inside the container reuses credentials acquired on
	// the host instead of launching fresh device-authorization flows.
	// Path resolution differs by privilege: non-root on the host resolves
	// the base to ~/.config/pelican, while the container runs as root and
	// resolves it to /etc/pelican. Mounted read-write: token refreshes
	// are written back to the host wallet.
	if home, err := os.UserHomeDir(); err == nil {
		hostBase := filepath.Join(home, ".config", "pelican")
		if err := os.MkdirAll(hostBase, 0700); err == nil {
			args = append(args, "-v", hostBase+":/etc/pelican")
		}
	}
	if opts.EncryptKeyPath != "" {
		args = append(args, "-v", opts.EncryptKeyPath+":/run/pelfs/encrypt-key:ro")
	}
	if opts.StatsPath != "" {
		// The summary must outlive the container; mount the target
		// directory and let the in-container pelfs write into it.
		args = append(args, "-v", filepath.Dir(opts.StatsPath)+":/run/pelfs/stats")
	}
	args = append(args, passthroughEnv()...)
	args = append(args, image, "/usr/local/bin/pelfs", "shell",
		"--state-dir", "/var/tmp/pelfs", "--shell", "/bin/sh")
	args = append(args, opts.ExtraArgs...)
	args = append(args, opts.PrefixURL)

	fmt.Fprintf(os.Stderr, "pelfs: FUSE unavailable on host; launching container (%s)\n", image)
	cmd := exec.Command(docker, args...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err = cmd.Run()
	if ee, ok := err.(*exec.ExitError); ok {
		return ee.ExitCode(), nil
	}
	if err != nil {
		return 1, fmt.Errorf("docker run: %w", err)
	}
	return 0, nil
}

// passthroughEnv forwards Pelican-related environment variables into the
// container so configuration set on the host (log level, timeouts, ...)
// applies inside as well. Variables that name host filesystem paths are
// excluded: they would be meaningless (or harmful) in the container, where
// the config base and token file are provided by bind mounts instead.
func passthroughEnv() []string {
	excluded := map[string]bool{
		"PELICAN_CONFIGDIR":             true,
		"PELICAN_CONFIGBASE":            true,
		"PELICAN_CLIENT_CREDENTIALFILE": true,
	}
	var args []string
	for _, kv := range os.Environ() {
		name, _, ok := strings.Cut(kv, "=")
		if !ok {
			continue
		}
		if (strings.HasPrefix(name, "PELICAN_") && !excluded[name]) ||
			name == "BEARER_TOKEN" || name == "JFS_RSA_PASSPHRASE" {
			args = append(args, "-e", kv)
		}
	}
	return args
}

func isTerminal() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}
