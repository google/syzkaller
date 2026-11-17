// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

//go:build linux

package bwrap

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCheckProxyAddress(t *testing.T) {
	ctx := context.Background()
	for _, bad := range []string{
		"127.0.0.1:80",
		"[::1]:443",
		"[::ffff:127.0.0.1]:80",
		"[::ffff:10.0.0.1]:443",
		"[::ffff:100.64.0.1]:443",
		"[fc00::1]:443",
		"[fe80::1]:80",
		"10.0.0.1:443",
		"172.16.0.1:80",
		"192.168.1.1:443",
		"169.254.169.254:80",
		"100.64.0.1:443",
		"199.36.153.4:443",
		"199.36.153.8:443",
		"[2600:2d00:2:1000::1]:443",
		"[2600:2d00:2:2000::1]:443",
		"0.0.0.0:80",
		"8.8.8.8:22",
		"8.8.8.8:8080",
	} {
		_, _, err := checkProxyAddress(ctx, bad)
		assert.Error(t, err, "expected %s to be rejected", bad)
	}
	for _, good := range []string{
		"8.8.8.8:80",
		"8.8.8.8:443",
		"8.8.8.8:9418",
		"[2001:4860:4860::8888]:443",
	} {
		ips, port, err := checkProxyAddress(ctx, good)
		require.NoError(t, err, "expected %s to be allowed", good)
		require.NotEmpty(t, ips)
		assert.NotEmpty(t, port)
	}
}

func TestBwrapBindArgs(t *testing.T) {
	// Non-/tmp path has no synthetic ancestors.
	assert.Equal(t,
		[]string{"--ro-bind-try", "/var/lib/foo", "/var/lib/foo"},
		bwrapBindArgs("--ro-bind-try", "/var/lib/foo", []string{"/var/lib/foo"}),
	)

	// /tmp/<parent>/<child> locks synthetic parent /tmp/<parent> to 0555.
	assert.Equal(t,
		[]string{
			"--dir", "/tmp/parent", "--chmod", "0755", "/tmp/parent",
			"--bind-try", "/tmp/parent/work", "/tmp/parent/work",
			"--chmod", "0555", "/tmp/parent",
		},
		bwrapBindArgs("--bind-try", "/tmp/parent/work", []string{"/tmp/parent/work"}),
	)

	// Nested mount inside an already-bound /tmp directory must NOT chmod the bound parent.
	assert.Equal(t,
		[]string{"--ro-bind-try", "/tmp/parent/work/sub", "/tmp/parent/work/sub"},
		bwrapBindArgs("--ro-bind-try", "/tmp/parent/work/sub", []string{"/tmp/parent/work", "/tmp/parent/work/sub"}),
	)
}

func TestBwrapMountArgs(t *testing.T) {
	tests := []struct {
		name   string
		mounts map[string]bool
		want   []string
	}{
		{
			name: "no mounts",
		},
		{
			name:   "read-write child of a read-only parent",
			mounts: map[string]bool{"/src/build": true, "/src": false},
			want: []string{
				"--ro-bind-try", "/src", "/src",
				"--bind-try", "/src/build", "/src/build",
			},
		},
		{
			name:   "read-only child of a read-write parent",
			mounts: map[string]bool{"/work/ref": false, "/work": true},
			want: []string{
				"--bind-try", "/work", "/work",
				"--ro-bind-try", "/work/ref", "/work/ref",
			},
		},
		{
			name:   "sibling with a common name prefix",
			mounts: map[string]bool{"/a/b": false, "/a-b": true, "/a": false},
			want: []string{
				"--ro-bind-try", "/a", "/a",
				"--bind-try", "/a-b", "/a-b",
				"--ro-bind-try", "/a/b", "/a/b",
			},
		},
		{
			name:   "synthetic parent of nested mounts in tmp",
			mounts: map[string]bool{"/tmp/parent/work/sub": false, "/tmp/parent/work": true},
			want: []string{
				"--dir", "/tmp/parent", "--chmod", "0755", "/tmp/parent",
				"--bind-try", "/tmp/parent/work", "/tmp/parent/work",
				"--chmod", "0555", "/tmp/parent",
				"--ro-bind-try", "/tmp/parent/work/sub", "/tmp/parent/work/sub",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := bwrapMountArgs(test.mounts)
			require.NoError(t, err)
			assert.Equal(t, test.want, got)
		})
	}
	_, err := bwrapMountArgs(map[string]bool{"/": false, "/work": true})
	assert.Error(t, err)
}

func TestProxySocks5(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "proxied-ok")
	}))
	defer srv.Close()

	p, err := newProxy(t.TempDir(), func(ctx context.Context, hostPort string) (net.Conn, error) {
		if _, _, err := checkProxyAddress(ctx, hostPort); err != nil {
			return nil, err
		}
		var d net.Dialer
		return d.DialContext(ctx, "tcp", srv.Listener.Addr().String())
	})
	require.NoError(t, err)
	defer p.Close()

	proxyURL := "socks5h://localhost" + p.sockPath

	// Loopback target must be rejected.
	badCmd := exec.Command("curl", "-sS", "--proxy", proxyURL, "http://127.0.0.1:80/test")
	out, err := badCmd.CombinedOutput()
	require.Error(t, err)
	assert.Contains(t, string(out), "cannot complete SOCKS5 connection")

	// Disallowed port must be rejected.
	badPortCmd := exec.Command("curl", "-sS", "--proxy", proxyURL, "http://8.8.8.8:8080/test")
	out, err = badPortCmd.CombinedOutput()
	require.Error(t, err)
	assert.Contains(t, string(out), "cannot complete SOCKS5 connection")

	// Allowed public target and port must be proxied end-to-end.
	okCmd := exec.Command("curl", "-sS", "--proxy", proxyURL, "http://8.8.8.8:80/test")
	out, err = okCmd.CombinedOutput()
	require.NoError(t, err, "output: %s", out)
	assert.Equal(t, "proxied-ok", string(out))
}

func TestProxyGitConnect(t *testing.T) {
	if _, err := exec.LookPath("socat"); err != nil {
		if os.Getenv("CI") != "" {
			t.Fatalf("socat must be installed on CI: %v", err)
		}
		t.Skipf("skipping test: %v", err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				line, err := bufio.NewReader(c).ReadString('\n')
				if err == nil {
					_, _ = fmt.Fprintf(c, "ack:%s", line)
				}
			}(conn)
		}
	}()

	p, err := newProxy(t.TempDir(), func(ctx context.Context, hostPort string) (net.Conn, error) {
		if _, _, err := checkProxyAddress(ctx, hostPort); err != nil {
			return nil, err
		}
		var d net.Dialer
		return d.DialContext(ctx, "tcp", ln.Addr().String())
	})
	require.NoError(t, err)
	defer p.Close()

	// Loopback target must be blocked.
	badCmd := exec.Command(p.scriptPath, "127.0.0.1", "9418")
	badCmd.Stdin = strings.NewReader("hello\n")
	out, _ := badCmd.CombinedOutput()
	assert.Empty(t, string(out))

	// Oversized CONNECT line must be rejected promptly without proxying.
	conn, err := net.Dial("unix", p.sockPath)
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, conn.SetDeadline(time.Now().Add(5*time.Second)))
	_, err = conn.Write([]byte("CONNECT " + strings.Repeat("a", maxConnectLine+128) + ":9418\n"))
	require.NoError(t, err)
	resp, err := io.ReadAll(conn)
	if err != nil {
		// Server closing the socket with unread bytes in the receive buffer triggers ECONNRESET.
		assert.ErrorIs(t, err, syscall.ECONNRESET)
	}
	assert.Empty(t, resp)

	// Allowed target on port 9418 must stream data bidirectionally.
	okCmd := exec.Command(p.scriptPath, "8.8.8.8", "9418")
	okCmd.Stdin = strings.NewReader("hello-git\n")
	out, err = okCmd.CombinedOutput()
	require.NoError(t, err, "output: %s", out)
	assert.Equal(t, "ack:hello-git\n", string(out))
}

func TestWrap(t *testing.T) {
	uid, gid := requireBwrap(t)

	baseDir, err := os.MkdirTemp("", "bwrap-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(baseDir)
	require.NoError(t, os.Chmod(baseDir, 0755))

	workDir := filepath.Join(baseDir, "work")
	require.NoError(t, os.MkdirAll(workDir, 0755))
	require.NoError(t, os.Chown(workDir, int(uid), int(gid)))

	otherDir := filepath.Join(baseDir, "other")
	require.NoError(t, os.MkdirAll(otherDir, 0755))
	secretFile := filepath.Join(otherDir, "secret.txt")
	require.NoError(t, os.WriteFile(secretFile, []byte("secret-value"), 0644))
	require.NoError(t, os.Chown(otherDir, int(uid), int(gid)))
	require.NoError(t, os.Chown(secretFile, int(uid), int(gid)))

	// Verify HOME, CCACHE_DISABLE, and that unmounted paths are hidden.
	cmd := exec.Command("sh", "-c", fmt.Sprintf("echo $HOME:$CCACHE_DISABLE && test ! -e %q", secretFile))
	cmd.Dir = workDir
	require.NoError(t, Wrap(cmd, WithUser(uid, gid)))
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "output: %s", out)
	assert.Equal(t, "/home/syzkaller:1", strings.TrimSpace(string(out)))

	// Verify WithReadOnly allows reading but rejects writing.
	roCmd := exec.Command("sh", "-c", fmt.Sprintf("cat %q && ! touch %q/new 2>/dev/null", secretFile, otherDir))
	roCmd.Dir = workDir
	require.NoError(t, Wrap(roCmd, WithUser(uid, gid), WithReadOnly(otherDir)))
	out, err = roCmd.CombinedOutput()
	require.NoError(t, err, "output: %s", out)
	assert.Equal(t, "secret-value", strings.TrimSpace(string(out)))

	// Verify WithReadWrite allows writing.
	rwCmd := exec.Command("touch", filepath.Join(otherDir, "created"))
	rwCmd.Dir = workDir
	require.NoError(t, Wrap(rwCmd, WithUser(uid, gid), WithReadWrite(otherDir)))
	out, err = rwCmd.CombinedOutput()
	require.NoError(t, err, "output: %s", out)
	assert.FileExists(t, filepath.Join(otherDir, "created"))

	// Verify a nested RO mount inside workDir under /tmp does not chmod workDir on the host.
	nestedSub := filepath.Join(workDir, "sub")
	require.NoError(t, os.MkdirAll(nestedSub, 0755))
	require.NoError(t, os.Chown(nestedSub, int(uid), int(gid)))
	nestedCmd := exec.Command("touch", filepath.Join(workDir, "sibling"))
	nestedCmd.Dir = workDir
	require.NoError(t, Wrap(nestedCmd, WithUser(uid, gid), WithReadOnly(nestedSub)))
	out, err = nestedCmd.CombinedOutput()
	require.NoError(t, err, "output: %s", out)
	info, err := os.Stat(workDir)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0755), info.Mode().Perm())

	// Verify that the most specific mount determines the access mode.
	canWrite := func(file string, opts ...Option) bool {
		cmd := exec.Command("touch", file)
		cmd.Dir = workDir
		require.NoError(t, Wrap(cmd, append(opts, WithUser(uid, gid))...))
		return cmd.Run() == nil
	}
	// A read-only mount inside of the working directory.
	assert.True(t, canWrite(filepath.Join(workDir, "f1"), WithReadOnly(nestedSub)))
	assert.False(t, canWrite(filepath.Join(nestedSub, "f1"), WithReadOnly(nestedSub)))
	// The working directory stays writable if it is also requested read-only,
	// or is located inside of a read-only mount.
	assert.True(t, canWrite(filepath.Join(workDir, "f2"), WithReadOnly(workDir)))
	assert.True(t, canWrite(filepath.Join(workDir, "f3"), WithReadOnly(baseDir)))
	assert.False(t, canWrite(filepath.Join(otherDir, "f3"), WithReadOnly(baseDir)))
	// A read-write parent does not make its read-only child writable,
	// irrespective of the order of options.
	assert.False(t, canWrite(filepath.Join(otherDir, "f4"), WithReadWrite(baseDir), WithReadOnly(otherDir)))
	assert.False(t, canWrite(filepath.Join(otherDir, "f4"), WithReadOnly(otherDir), WithReadWrite(baseDir)))

	// Verify end-to-end proxying from inside bwrap's isolated network namespace.
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, "from-host-server")
	}))
	defer srv.Close()

	proxyDir := filepath.Join(baseDir, "proxy")
	require.NoError(t, os.MkdirAll(proxyDir, 0755))
	p, err := newProxy(proxyDir, func(ctx context.Context, hostPort string) (net.Conn, error) {
		if _, _, err := checkProxyAddress(ctx, hostPort); err != nil {
			return nil, err
		}
		var d net.Dialer
		return d.DialContext(ctx, "tcp", srv.Listener.Addr().String())
	})
	require.NoError(t, err)
	defer p.Close()
	require.NoError(t, os.Chown(p.sockPath, int(uid), int(gid)))

	netCmd := exec.Command("curl", "-sS", "http://8.8.8.8:80/hello")
	netCmd.Dir = workDir
	require.NoError(t, Wrap(netCmd, WithUser(uid, gid), withCustomProxy(p)))
	rawOut, err := netCmd.CombinedOutput()
	require.NoError(t, err, "output: %s", rawOut)
	assert.Equal(t, "from-host-server", string(bytes.TrimSpace(rawOut)))
}

func requireBwrap(t *testing.T) (uint32, uint32) {
	t.Helper()
	skip := func(msg string) {
		t.Helper()
		if os.Getenv("CI") != "" {
			t.Fatalf("bwrap tests must run on CI: %v", msg)
		}
		t.Skipf("skipping bwrap test: %v", msg)
	}
	if syscall.Getuid() != 0 {
		skip("requires root")
	}
	u, err := user.Lookup("syzkaller")
	if err != nil {
		skip(err.Error())
	}
	uid, err := strconv.ParseUint(u.Uid, 10, 32)
	require.NoError(t, err)
	gid, err := strconv.ParseUint(u.Gid, 10, 32)
	require.NoError(t, err)
	if err := Available(uint32(uid), uint32(gid)); err != nil {
		skip(err.Error())
	}
	return uint32(uid), uint32(gid)
}
