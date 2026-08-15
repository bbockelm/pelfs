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
)

// DefaultImage is a small image with a shell and CA certificates; the pelfs
// linux binary is bind-mounted into it, so no image build is required.
const DefaultImage = "alpine:3.21"

// Options for the containerized run.
type Options struct {
	PrefixURL      string
	TokenPath      string   // host path of bearer token file ("" = none found)
	EncryptKeyPath string   // host path of the encryption private key ("" = none)
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
	if opts.EncryptKeyPath != "" {
		args = append(args, "-v", opts.EncryptKeyPath+":/run/pelfs/encrypt-key:ro")
	}
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

func isTerminal() bool {
	fi, err := os.Stdin.Stat()
	if err != nil {
		return false
	}
	return fi.Mode()&os.ModeCharDevice != 0
}
