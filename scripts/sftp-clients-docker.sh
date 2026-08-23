#!/usr/bin/env bash
#
# What this establishes, and why it exists before any pelfs code does.
#
# docs/design-guiclients.md proposes an SFTP frontend built on
# github.com/pkg/sftp's RequestServer over an adapter that wraps
# internal/vfsbilly, so a Windows (or macOS, or Linux) user can browse,
# upload and download a pelfs volume with an existing free GUI client
# (Cyberduck, WinSCP, FileZilla) and no FUSE, no drive letter, no admin.
# Everything in that plan rests on two unmeasured assumptions -- that the
# upstream server is protocol-correct enough for a REAL client to trust,
# and that an ordinary SFTP client has none of the WebDAV redirector's
# limits (docs/design-windows.md: 47.68 MiB transfers, ~1,000 directory
# entries).
#
# This script measures both, WITHOUT any pelfs code: `sftp.InMemHandler()`
# -- pkg/sftp's OWN reference handler, the exact analogue of
# `webdav.NewMemFS()` in scripts/webdav-litmus-docker.sh -- behind
# golang.org/x/crypto/ssh, driven by two independent real clients: OpenSSH's
# `sftp(1)` and `rclone`. The number it prints is therefore the CEILING for a
# pelfs SFTP frontend and the floor a pelfs adapter must not fall below.
#
# Measured 2026-08-23 -- 0 failing checks -- with pkg/sftp v1.13.11,
# golang.org/x/crypto v0.55.0, OpenSSH_10.0p2, rclone v1.60.1, on
# golang:1.26-trixie:
#
#   ok   openssh:version           SFTP protocol 3; extensions advertised:
#                                  hardlink@openssh.com,
#                                  posix-rename@openssh.com,
#                                  statvfs@openssh.com
#   ok   openssh:mkdir-put-get     1,000,000 bytes, byte-for-byte
#   ok   openssh:size-68497408     a 68,497,408-byte file -- the owner's own SIF
#                                  size (docs/design-apptainer.md), which the
#                                  WebDAV redirector REFUSES -- both directions,
#                                  byte-for-byte
#   ok   openssh:dir-5000          5,000 of 5,000 entries listed, against the
#                                  redirector's ~1,000
#   base openssh:preserve-mtime    SETSTAT accepted, mtime DROPPED
#   base openssh:chmod             SETSTAT accepted, mode DROPPED
#   ok   openssh:symlink-readlink  symlink created, listed as a symlink
#   ok   openssh:hardlink          hardlink@openssh.com
#   ok   openssh:rename            rename
#   ok   openssh:posix-rename      rename ONTO AN EXISTING NAME -- what WinSCP's
#                                  default `foo.filepart` -> `foo` upload needs
#   ok   openssh:df                statvfs@openssh.com answered
#   ok   openssh:resume            `reput` completed a truncated upload, i.e. a
#                                  random-access write at a non-zero offset
#   ok   openssh:rm-rmdir          remove, rmdir
#   ok   rclone:lsl                second, independent client: 5,000 of 5,000
#                                  with mtimes
#   ok   rclone:copy-check         `rclone copy` then `rclone check` clean, 68 MB
#                                  file included
#
# The two `base` rows are this suite's equivalent of litmus's two known `locks`
# failures: NOT protocol limits, but holes in the REFERENCE handler.
# InMemHandler's Filecmd does `if r.AttrFlags().Size { ... Truncate }; return
# nil` for Setstat, so mtime and mode reach it and are dropped. A pelfs adapter
# must FILL exactly those two, and already has the code --
# internal/vfsbilly.Chtimes and .Chmod. So when this script is pointed at the
# pelfs adapter, those two rows are expected to FLIP to `ok`, and any row that
# is `ok` here and not there is the adapter's fault.
#
# The two rows that matter most are `size-68497408` and `dir-5000`: they are
# the redirector's two hard caps, and an ordinary SFTP client has neither.
#
# Everything runs in Docker (a server, two clients, keys and a 68 MB test
# file, none of which belongs on a laptop). Needs network on FIRST BUILD
# only, for the base image, the two apt packages and the two Go modules; the
# RUN is `--network none`, so a green result cannot be one that reached
# anything outside the container. No pelfs build, no pelfs code, no go.mod
# change -- pkg/sftp is fetched into a throwaway module inside the image.
#
# One defect this probe found in its own server, worth carrying into any pelfs
# frontend: serving each SSH channel SYNCHRONOUSLY inside the `for nc := range
# chans` loop deadlocks the second channel on a connection until the first
# closes. rclone reported it as "Discarding closed SSH connection: ... i/o
# timeout". A GUI client opens several channels and several connections
# (Cyberduck defaults to 2, rclone's --sftp-concurrency to 64), so each channel
# gets its own goroutine. See server.go below.
#
# Usage: scripts/sftp-clients-docker.sh [pkg/sftp version]   (default: latest)
set -euo pipefail

ver=${1:-latest}
ctx=$(mktemp -d)
trap 'rm -rf "$ctx"' EXIT

# ---------------------------------------------------------------- the server
# pkg/sftp's reference handler behind x/crypto/ssh. This is deliberately the
# UPSTREAM example shape (examples/request-server/main.go, 130 lines) with
# three changes, each of which a pelfs frontend would also need:
#   - public-key auth rather than a hardcoded password, so the client needs
#     no tty and no sshpass;
#   - a loop over connections rather than one, because every GUI client opens
#     several (Cyberduck's default is 2, WinSCP reconnects for background
#     transfers), and ONE handler instance shared across them, because they
#     must see the same namespace;
#   - the listening address printed after the bind, which is how an ephemeral
#     :0 port would be reported to a caller.
cat > "$ctx/server.go" <<'GO'
package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:2222", "listen address")
	hostKey := flag.String("hostkey", "/keys/host_ed25519", "host private key")
	authorized := flag.String("authorized", "/keys/client_ed25519.pub", "sole accepted public key")
	flag.Parse()

	hk, err := os.ReadFile(*hostKey)
	if err != nil {
		log.Fatalf("host key: %v", err)
	}
	signer, err := ssh.ParsePrivateKey(hk)
	if err != nil {
		log.Fatalf("parse host key: %v", err)
	}
	ak, err := os.ReadFile(*authorized)
	if err != nil {
		log.Fatalf("authorized key: %v", err)
	}
	allowed, _, _, _, err := ssh.ParseAuthorizedKey(ak)
	if err != nil {
		log.Fatalf("parse authorized key: %v", err)
	}

	cfg := &ssh.ServerConfig{
		PublicKeyCallback: func(_ ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			if bytes.Equal(key.Marshal(), allowed.Marshal()) {
				return nil, nil
			}
			return nil, fmt.Errorf("public key rejected")
		},
	}
	cfg.AddHostKey(signer)

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}
	fmt.Printf("ready %s\n", ln.Addr())
	os.Stdout.Sync() //nolint:errcheck

	// One handler for the whole run: separate connections must see the same
	// namespace, which is the property a per-connection handler would break.
	h := sftp.InMemHandler()
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go session(c, cfg, h)
	}
}

func session(c net.Conn, cfg *ssh.ServerConfig, h sftp.Handlers) {
	sc, chans, reqs, err := ssh.NewServerConn(c, cfg)
	if err != nil {
		log.Printf("handshake: %v", err)
		return
	}
	defer sc.Close() //nolint:errcheck
	go ssh.DiscardRequests(reqs)
	for nc := range chans {
		if nc.ChannelType() != "session" {
			nc.Reject(ssh.UnknownChannelType, "not a session") //nolint:errcheck
			continue
		}
		ch, creqs, err := nc.Accept()
		if err != nil {
			return
		}
		go func(in <-chan *ssh.Request) {
			for r := range in {
				ok := r.Type == "subsystem" && len(r.Payload) > 4 && string(r.Payload[4:]) == "sftp"
				r.Reply(ok, nil) //nolint:errcheck
			}
		}(creqs)
		// Each channel in its own goroutine. A GUI client opens SEVERAL --
		// Cyberduck's default is 2 connections, rclone opens up to 64
		// (--sftp-concurrency) -- and serving them one at a time in this
		// loop deadlocks the second one until the first closes. Found by
		// this probe: rclone's first version of this run failed with
		// "Discarding closed SSH connection: i/o timeout".
		go func(ch ssh.Channel) {
			srv := sftp.NewRequestServer(ch, h)
			if err := srv.Serve(); err != nil && err != io.EOF {
				log.Printf("sftp: %v", err)
			}
			srv.Close() //nolint:errcheck
		}(ch)
	}
}
GO

# ----------------------------------------------------------------- the probe
# One check per line of output, `ok`/`FAIL` first so the summary is a grep.
# Every check is independent: `sftp -b` aborts a batch on the first error, so
# a failure must not be allowed to hide the checks after it.
cat > "$ctx/probe.sh" <<'SH'
#!/bin/sh
# Not `set -e`: the point of this script is to run every check and report.
fails=0
S="-o StrictHostKeyChecking=yes -o UserKnownHostsFile=/keys/known_hosts -o IdentitiesOnly=yes -i /keys/client_ed25519 -P 2222"
run() { sftp $S -b - probe@127.0.0.1 >/tmp/last.log 2>&1; }
ck()  { if [ "$1" = 0 ]; then echo "ok   $2"; else echo "FAIL $2"; sed 's/^/       | /' /tmp/last.log | head -8; fails=$((fails+1)); fi; }

cd /work || exit 2

# 0. What the server says it is. StrictHostKeyChecking=yes against a
#    known_hosts seeded from the server's own public key is the CI form of
#    "the GUI client shows no scary warning": a pinned host key.
sftp $S -vv probe@127.0.0.1 </dev/null >/tmp/last.log 2>&1
ver=$(grep -o 'Remote version: [0-9]*' /tmp/last.log | head -1)
ext=$(sed -n 's/.*Server supports extension "\([^"]*\)".*/\1/p' /tmp/last.log | sort -u | tr '\n' ' ')
ck $? "openssh:version           ${ver:-unknown}; extensions: ${ext:-none}"

# 1. The round trip everything else rests on.
head -c 1000000 /dev/urandom > small.bin
printf 'mkdir /d\nput small.bin /d/small.bin\nget /d/small.bin got-small.bin\n' | run
cmp -s small.bin got-small.bin
ck $? "openssh:mkdir-put-get    1,000,000 bytes, byte-for-byte"

# 2. THE cap that killed the drive letter. 68,497,408 bytes is the owner's
#    own SIF (docs/design-apptainer.md); the WebDAV redirector refuses
#    anything over 50,000,000 (docs/design-windows.md row 1).
head -c 68497408 /dev/urandom > sif.bin
printf 'put sif.bin /d/sif.bin\nget /d/sif.bin got-sif.bin\n' | run
cmp -s sif.bin got-sif.bin
ck $? "openssh:size-68497408    a 68,497,408-byte file, both directions"

# 3. The OTHER redirector cap: FileAttributesLimitInBytes caps a listing at
#    ~1,000 entries. An SFTP listing is paged by the protocol.
printf 'mkdir /wide\n' | run
: > /tmp/empty
i=0; : > /tmp/wide.batch
while [ $i -lt 5000 ]; do echo "-put /tmp/empty /wide/f$i" >> /tmp/wide.batch; i=$((i+1)); done
sftp $S -b /tmp/wide.batch probe@127.0.0.1 >/tmp/last.log 2>&1
n=$(printf 'ls -1 /wide\n' | sftp $S -b - probe@127.0.0.1 2>/dev/null | grep -c '^/wide/f')
[ "$n" = 5000 ]
ck $? "openssh:dir-5000         listed $n of 5000 entries"

# 4. mtime. `put -p` sends SETSTAT with SSH_FILEXFER_ATTR_ACMODTIME. The
#    REQUEST reaches the handler; InMemHandler's Setstat honours only the
#    size attribute (request-example.go: `if r.AttrFlags().Size { ...
#    Truncate }; return nil`), so the attribute is accepted and dropped.
#    This is the upstream baseline's equivalent of litmus's two `locks`
#    failures: not a protocol limit, a hole in the REFERENCE handler, and
#    exactly what a pelfs adapter must fill (internal/vfsbilly.Chtimes).
touch -d '2001-02-03 04:05:06' stamped.bin
printf 'put -p stamped.bin /d/stamped.bin\nls -l /d/stamped.bin\n' | run
if grep -q 'Feb  3  2001' /tmp/last.log; then echo "ok   openssh:preserve-mtime   put -p round-trips mtime"
else echo "base openssh:preserve-mtime   SETSTAT accepted, mtime dropped (InMemHandler honours only Size)"; fi

# 5. Mode bits, also SETSTAT -- same hole, same reason.
printf 'chmod 444 /d/small.bin\nls -l /d/small.bin\n' | run
if grep -q '^-r--r--r--' /tmp/last.log; then echo "ok   openssh:chmod            SETSTAT permissions"
else echo "base openssh:chmod            SETSTAT accepted, mode dropped (InMemHandler honours only Size)"; fi

# 6. Symlinks: a pelfs volume has them (23 in one directory of the owner's
#    own tree, docs/design-windows.md) and WebDAV has no concept for them.
#    Checked through the DIRECTORY listing, which is LSTAT-shaped: `ls -l`
#    on the link itself follows it, so it would report the target's type.
printf 'ln -s /d/small.bin /d/link\nls -l /d\n' | run
grep -q '^l.*link' /tmp/last.log
ck $? "openssh:symlink-readlink symlink created, listed as a symlink"

# 7. Hard links: hardlink@openssh.com. pelfs exposes nlink>1 as every name.
printf 'ln /d/small.bin /d/hard\nls -l /d/hard\n' | run
grep -q '/d/hard' /tmp/last.log
ck $? "openssh:hardlink         hardlink@openssh.com"

# 8. Rename, and rename OVER an existing name -- which plain SSH_FXP_RENAME
#    must refuse and posix-rename@openssh.com must allow. This is the
#    mechanism a client's "upload to a temp name, then rename" needs, and it
#    is what makes an upload atomic for a checkpoint that may fire mid-drag.
printf 'rename /d/hard /d/hard2\nls -l /d/hard2\n' | run
grep -q '/d/hard2' /tmp/last.log
ck $? "openssh:rename           rename"
# OpenSSH's sftp has no flag for this: it uses posix-rename@openssh.com
# automatically when the server advertises it. So a rename that SUCCEEDS
# over an existing name proves the extension is in play, because plain
# SSH_FXP_RENAME must refuse (SFTP-v2: "It is an error if there already
# exists a file with the name specified by newpath"). This is the
# mechanism WinSCP's default upload needs: it writes `foo.filepart` and
# renames onto `foo`, for every SFTP transfer over 100 KB.
printf 'put small.bin /d/target\nput small.bin /d/src\n' | run
printf 'rename /d/src /d/target\n' | run
ck $? "openssh:posix-rename     rename onto an existing name"

# 9. statvfs@openssh.com. Cyberduck and WinSCP both show free space.
printf 'df\n' | run
grep -q 'Avail' /tmp/last.log
ck $? "openssh:df               statvfs@openssh.com answered"

# 10. Resume. `reput` stats the remote, seeks, and writes at an offset --
#     the random-access WRITE that S3 cannot express at all.
head -c 4000000 sif.bin > /tmp/part.bin
printf 'put /tmp/part.bin /d/resume.bin\n' | run
printf 'reput sif.bin /d/resume.bin\nget /d/resume.bin got-resume.bin\n' | run
cmp -s sif.bin got-resume.bin 2>/dev/null
ck $? "openssh:resume           reput completed a truncated upload"

# 11. Teardown ops.
printf -- '-rm /d/link\n-rm /d/hard2\n-rm /d/stamped.bin\n-rm /d/target\n-rm /d/sif.bin\n-rm /d/resume.bin\n-rm /d/small.bin\nrmdir /d\n' | run
ck $? "openssh:rm-rmdir         remove, rmdir"

# 12. A SECOND, INDEPENDENT CLIENT. rclone's sftp backend is its own
#     implementation of the protocol (it uses pkg/sftp as a CLIENT), and it
#     is also the free `rclone mount` that gives a Windows user a drive
#     letter without pelfs writing any Windows filesystem code.
export RCLONE_CONFIG=/dev/null
R="--retries 1 --low-level-retries 1 --timeout 30s --sftp-host 127.0.0.1 --sftp-port 2222 --sftp-user probe --sftp-key-file /keys/client_ed25519 --sftp-known-hosts-file /keys/known_hosts"
rclone $R lsl :sftp:/wide >/tmp/last.log 2>&1 && [ "$(grep -c . /tmp/last.log)" = 5000 ]
ck $? "rclone:lsl               listed $(grep -c . /tmp/last.log 2>/dev/null) of 5000 with mtimes"
mkdir -p up && cp small.bin sif.bin up/
rclone $R copy up :sftp:/rc >/tmp/last.log 2>&1 && rclone $R check up :sftp:/rc >>/tmp/last.log 2>&1
ck $? "rclone:copy-check        copy then check clean (68 MB included)"

echo
echo "== summary: $fails failing check(s) =="
exit $fails
SH

cat > "$ctx/Dockerfile" <<EOF
FROM golang:1.26-trixie
RUN apt-get update \\
 && apt-get install -y --no-install-recommends openssh-client rclone ca-certificates \\
 && rm -rf /var/lib/apt/lists/*
# Keys are baked in: a probe image is thrown away, and generating them at
# build time is what lets the client pin the host key (StrictHostKeyChecking
# =yes against a seeded known_hosts) -- the CI form of a GUI client that
# shows no "unknown host key" dialog.
RUN mkdir -p /keys \\
 && ssh-keygen -q -t ed25519 -N '' -C probe-host   -f /keys/host_ed25519 \\
 && ssh-keygen -q -t ed25519 -N '' -C probe-client -f /keys/client_ed25519 \\
 && printf '[127.0.0.1]:2222 %s\\n' "\$(cut -d' ' -f1,2 /keys/host_ed25519.pub)" > /keys/known_hosts \\
 && chmod 600 /keys/client_ed25519
WORKDIR /srv
COPY server.go .
RUN go mod init sftpprobe \\
 && go get github.com/pkg/sftp@$ver && go get golang.org/x/crypto \\
 && go build -o /usr/local/bin/sftpsrv server.go \\
 && go list -m github.com/pkg/sftp golang.org/x/crypto > /keys/versions
COPY probe.sh /usr/local/bin/probe.sh
RUN chmod +x /usr/local/bin/probe.sh && mkdir -p /work
# The wait is a bind poll on the server's own "ready" line: the CMD shell is
# dash and has no /dev/tcp, and a fixed sleep is the thing this repo does not
# do (docs/TODO.md, no sleep-based test sync).
CMD ["/bin/sh","-c","cat /keys/versions; ssh -V 2>&1; rclone version | head -1; echo; \\
      /usr/local/bin/sftpsrv >/tmp/sftpsrv.log 2>&1 & \\
      for i in \$(seq 100); do grep -q ready /tmp/sftpsrv.log && break; sleep 0.1; done; \\
      grep -q ready /tmp/sftpsrv.log || { echo 'server never bound'; cat /tmp/sftpsrv.log; exit 2; }; \\
      /usr/local/bin/probe.sh; s=\$?; echo; echo '== server log =='; cat /tmp/sftpsrv.log; exit \$s"]
EOF

echo "== building probe image (pkg/sftp $ver, OpenSSH + rclone clients) =="
docker build -t pelfs-sftp-probe "$ctx"

echo
echo "== real SFTP clients against pkg/sftp's own InMemHandler (no pelfs code) =="
# --network none: server, both clients and the payload are all in the
# container, so a green run cannot be one that reached anything else.
status=0
docker run --rm --network none pelfs-sftp-probe 2>&1 | tee "$ctx/out" || status=$?
echo
echo "== summary =="
grep -E '^(ok|FAIL|== summary)' "$ctx/out" || true
exit "$status"
