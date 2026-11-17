// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

//go:build linux

package bwrap

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
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
		"0.0.0.1:80",
		"168.63.129.16:80",
		"192.0.0.1:80",
		"192.0.2.1:80",
		"198.51.100.1:80",
		"203.0.113.1:80",
		"192.88.99.1:80",
		"198.18.0.1:80",
		"240.0.0.1:80",
		"[::127.0.0.1]:80",
		"[64:ff9b::7f00:1]:80",
		"[64:ff9b:1::1]:80",
		"[2001::1]:443",
		"[2001:db8::1]:443",
		"[2002:7f00:1::1]:443",
		"[fec0::1]:443",
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
		[]string{"--ro-bind", "/var/lib/foo", "/var/lib/foo"},
		bwrapBindArgs("--ro-bind", "/var/lib/foo", []string{"/var/lib/foo"}),
	)

	// /tmp/<parent>/<child> locks synthetic parent /tmp/<parent> to 0555.
	assert.Equal(t,
		[]string{
			"--dir", "/tmp/parent", "--chmod", "0755", "/tmp/parent",
			"--bind", "/tmp/parent/work", "/tmp/parent/work",
			"--chmod", "0555", "/tmp/parent",
		},
		bwrapBindArgs("--bind", "/tmp/parent/work", []string{"/tmp/parent/work"}),
	)

	// Nested mount inside an already-bound /tmp directory must NOT chmod the bound parent.
	assert.Equal(t,
		[]string{"--ro-bind", "/tmp/parent/work/sub", "/tmp/parent/work/sub"},
		bwrapBindArgs("--ro-bind", "/tmp/parent/work/sub", []string{"/tmp/parent/work", "/tmp/parent/work/sub"}),
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
				"--ro-bind", "/src", "/src",
				"--bind", "/src/build", "/src/build",
			},
		},
		{
			name:   "read-only child of a read-write parent",
			mounts: map[string]bool{"/work/ref": false, "/work": true},
			want: []string{
				"--bind", "/work", "/work",
				"--ro-bind", "/work/ref", "/work/ref",
			},
		},
		{
			name:   "sibling with a common name prefix",
			mounts: map[string]bool{"/a/b": false, "/a-b": true, "/a": false},
			want: []string{
				"--ro-bind", "/a", "/a",
				"--bind", "/a-b", "/a-b",
				"--ro-bind", "/a/b", "/a/b",
			},
		},
		{
			name:   "synthetic parent of nested mounts in tmp",
			mounts: map[string]bool{"/tmp/parent/work/sub": false, "/tmp/parent/work": true},
			want: []string{
				"--dir", "/tmp/parent", "--chmod", "0755", "/tmp/parent",
				"--bind", "/tmp/parent/work", "/tmp/parent/work",
				"--chmod", "0555", "/tmp/parent",
				"--ro-bind", "/tmp/parent/work/sub", "/tmp/parent/work/sub",
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
	for _, forbidden := range []string{
		"/", "/tmp", "/proc", "/proc/self", "/dev", "/dev/shm",
		"/sys", "/run", "/etc", "/etc/shadow", "/boot",
	} {
		_, err := bwrapMountArgs(map[string]bool{forbidden: false, "/work": true})
		assert.Error(t, err, "expected %s to be rejected", forbidden)
	}
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
				sc := bufio.NewScanner(c)
				for sc.Scan() {
					_, _ = fmt.Fprintf(c, "ack:%s\n", sc.Text())
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

	// Loopback target must be blocked without hanging even if the caller (like git's
	// atexit handler) waits for GIT_PROXY_COMMAND to exit before closing stdin.
	badCmd := exec.Command(p.scriptPath, "127.0.0.1", "9418")
	badStdin, err := badCmd.StdinPipe()
	require.NoError(t, err)
	defer badStdin.Close()
	var badOut bytes.Buffer
	badCmd.Stdout = &badOut
	require.NoError(t, badCmd.Start())
	_, err = badStdin.Write([]byte("hello\n"))
	require.NoError(t, err)
	waitDone := make(chan error, 1)
	go func() {
		waitDone <- badCmd.Wait()
	}()
	select {
	case <-waitDone:
	case <-time.After(5 * time.Second):
		_ = badCmd.Process.Kill()
		t.Fatal("git-proxy.sh hung when proxy closed connection with stdin still open")
	}
	assert.Empty(t, badOut.String())

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

	// Allowed target on port 9418 must stream data bidirectionally while stdin remains open
	// (matching git's GIT_PROXY_COMMAND protocol), including unbracketed IPv6 literals passed by git.
	for _, host := range []string{"8.8.8.8", "2001:4860:4860::8888"} {
		okCmd := exec.Command(p.scriptPath, host, "9418")
		okStdin, err := okCmd.StdinPipe()
		require.NoError(t, err)
		okStdout, err := okCmd.StdoutPipe()
		require.NoError(t, err)
		require.NoError(t, okCmd.Start())
		_, err = okStdin.Write([]byte("hello-git\n"))
		require.NoError(t, err)
		reply, err := bufio.NewReader(okStdout).ReadString('\n')
		require.NoError(t, err)
		assert.Equal(t, "ack:hello-git\n", reply, "host=%s", host)
		require.NoError(t, okStdin.Close())
		require.NoError(t, okCmd.Wait())
	}

	// Unbracketed IPv6 loopback must also be bracketed properly and rejected by checkProxyAddress.
	v6BadOut, _ := exec.Command(p.scriptPath, "::1", "9418").Output()
	assert.Empty(t, v6BadOut)
}

func TestProxyLifecycle(t *testing.T) {
	accepted := make(chan struct{}, maxConcurrentConns+4)
	remoteClosed := make(chan struct{}, maxConcurrentConns+4)
	dial := func(ctx context.Context, hostPort string) (net.Conn, error) {
		local, remote := net.Pipe()
		accepted <- struct{}{}
		go func() {
			defer remote.Close()
			_, _ = io.Copy(io.Discard, remote)
			remoteClosed <- struct{}{}
		}()
		return local, nil
	}
	hp := &proxy{idleTimeout: 60 * time.Millisecond, dial: dial}

	// 1. Client closing its side must immediately close the upstream connection.
	c1, s1 := net.Pipe()
	go hp.handleConn(t.Context(), s1)
	_, err := c1.Write([]byte("CONNECT 8.8.8.8:9418\n"))
	require.NoError(t, err)
	require.NoError(t, c1.Close())
	select {
	case <-remoteClosed:
	case <-time.After(2 * time.Second):
		t.Fatal("upstream connection was not closed after client disconnected")
	}

	// 2. Completely idle connections must close once idleTimeout elapses.
	cIdle, sIdle := net.Pipe()
	defer cIdle.Close()
	go hp.handleConn(t.Context(), sIdle)
	_, err = cIdle.Write([]byte("CONNECT 8.8.8.8:9418\n"))
	require.NoError(t, err)
	select {
	case <-remoteClosed:
	case <-time.After(2 * time.Second):
		t.Fatal("idle connection was not closed after idleTimeout")
	}
	_, err = io.ReadAll(cIdle)
	require.NoError(t, err)

	// 3. Active unidirectional streaming past idleTimeout must not be aborted.
	streamProxy := &proxy{
		idleTimeout: 60 * time.Millisecond,
		dial: func(ctx context.Context, hostPort string) (net.Conn, error) {
			local, remote := net.Pipe()
			go func() {
				defer remote.Close()
				for range 6 {
					time.Sleep(25 * time.Millisecond)
					if _, err := remote.Write([]byte("x")); err != nil {
						return
					}
				}
			}()
			return local, nil
		},
	}
	cStream, sStream := net.Pipe()
	defer cStream.Close()
	go streamProxy.handleConn(t.Context(), sStream)
	_, err = cStream.Write([]byte("CONNECT 8.8.8.8:9418\n"))
	require.NoError(t, err)
	got, err := io.ReadAll(cStream)
	require.NoError(t, err)
	assert.Equal(t, "xxxxxx", string(got))

	// Drain accepted token from sub-tests 1 and 2 before testing the concurrency limit.
	for len(accepted) > 0 {
		<-accepted
	}

	// 4. Concurrency is capped at maxConcurrentConns; queued connections proceed once a
	// slot frees up, and Close cancels all active connections and removes git-proxy.sh.
	p, err := newProxy(t.TempDir(), dial)
	require.NoError(t, err)
	defer p.Close()
	holds := make([]net.Conn, maxConcurrentConns)
	for i := range holds {
		c, err := net.Dial("unix", p.sockPath)
		require.NoError(t, err)
		defer c.Close()
		_, err = c.Write([]byte("CONNECT 8.8.8.8:9418\n"))
		require.NoError(t, err)
		holds[i] = c
	}
	for range maxConcurrentConns {
		<-accepted
	}

	extra, err := net.Dial("unix", p.sockPath)
	require.NoError(t, err)
	defer extra.Close()
	_, err = extra.Write([]byte("CONNECT 8.8.8.8:9418\n"))
	require.NoError(t, err)
	select {
	case <-accepted:
		t.Fatal("exceeded maxConcurrentConns")
	case <-time.After(50 * time.Millisecond):
	}

	require.NoError(t, holds[0].Close())
	<-remoteClosed
	select {
	case <-accepted:
	case <-time.After(2 * time.Second):
		t.Fatal("queued connection did not proceed after slot freed")
	}

	assert.FileExists(t, p.scriptPath)
	require.NoError(t, p.Close())
	assert.NoFileExists(t, p.scriptPath)
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

	// Verify HOME, CCACHE_DISABLE, Rust env forwarding, WithEnv, zero capabilities, scrubbed env, and hidden paths.
	t.Setenv("GOOGLE_API_KEY", "top-secret-api-key")
	t.Setenv("RUSTUP_HOME", "/usr/local/rustup")
	t.Setenv("CARGO_HOME", "/usr/local/cargo")
	cmd := exec.Command("sh", "-c", fmt.Sprintf(
		"echo $HOME:$CCACHE_DISABLE:$RUSTUP_HOME:$CARGO_HOME:$EXPLICIT_VAR:${GOOGLE_API_KEY:-empty} && "+
			"! grep -qa top-secret-api-key /proc/1/environ && "+
			"grep -q '^CapEff:\t0000000000000000$' /proc/self/status && test ! -e %q",
		secretFile))
	cmd.Dir = workDir
	require.NoError(t, Wrap(cmd, WithEnv("EXPLICIT_VAR=allowed-val")))
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "output: %s", out)
	assert.Equal(t, "/home/syzkaller:1:/usr/local/rustup:/usr/local/cargo:allowed-val:empty",
		strings.TrimSpace(string(out)))

	// Verify WithReadOnly allows reading but rejects writing.
	roCmd := exec.Command("sh", "-c", fmt.Sprintf("cat %q && ! touch %q/new 2>/dev/null", secretFile, otherDir))
	roCmd.Dir = workDir
	require.NoError(t, Wrap(roCmd, WithReadOnly(otherDir)))
	out, err = roCmd.CombinedOutput()
	require.NoError(t, err, "output: %s", out)
	assert.Equal(t, "secret-value", strings.TrimSpace(string(out)))

	// Verify WithReadWrite allows writing.
	rwCmd := exec.Command("touch", filepath.Join(otherDir, "created"))
	rwCmd.Dir = workDir
	require.NoError(t, Wrap(rwCmd, WithReadWrite(otherDir)))
	out, err = rwCmd.CombinedOutput()
	require.NoError(t, err, "output: %s", out)
	assert.FileExists(t, filepath.Join(otherDir, "created"))

	// Verify a nested RO mount inside workDir under /tmp does not chmod workDir on the host.
	nestedSub := filepath.Join(workDir, "sub")
	require.NoError(t, os.MkdirAll(nestedSub, 0755))
	require.NoError(t, os.Chown(nestedSub, int(uid), int(gid)))
	nestedCmd := exec.Command("touch", filepath.Join(workDir, "sibling"))
	nestedCmd.Dir = workDir
	require.NoError(t, Wrap(nestedCmd, WithReadWrite(workDir), WithReadOnly(nestedSub)))
	out, err = nestedCmd.CombinedOutput()
	require.NoError(t, err, "output: %s", out)
	info, err := os.Stat(workDir)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0755), info.Mode().Perm())

	// Verify that cmd.Dir defaults to read-only and the most specific mount determines the access mode.
	canWrite := func(file string, opts ...Option) bool {
		cmd := exec.Command("touch", file)
		cmd.Dir = workDir
		require.NoError(t, Wrap(cmd, opts...))
		return cmd.Run() == nil
	}
	assert.False(t, canWrite(filepath.Join(workDir, "f0")))
	// A read-only mount inside of a read-write working directory.
	assert.True(t, canWrite(filepath.Join(workDir, "f1"), WithReadWrite(workDir), WithReadOnly(nestedSub)))
	assert.False(t, canWrite(filepath.Join(nestedSub, "f1"), WithReadWrite(workDir), WithReadOnly(nestedSub)))
	// An explicit WithReadWrite wins over WithReadOnly on the same path or an ancestor.
	assert.True(t, canWrite(filepath.Join(workDir, "f2"), WithReadWrite(workDir), WithReadOnly(workDir)))
	assert.True(t, canWrite(filepath.Join(workDir, "f3"), WithReadWrite(workDir), WithReadOnly(baseDir)))
	assert.False(t, canWrite(filepath.Join(otherDir, "f3"), WithReadWrite(workDir), WithReadOnly(baseDir)))
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
	require.NoError(t, Wrap(netCmd, withCustomProxy(p)))
	rawOut, err := netCmd.CombinedOutput()
	require.NoError(t, err, "output: %s", rawOut)
	assert.Equal(t, "from-host-server", string(bytes.TrimSpace(rawOut)))
}

func TestWrapPaths(t *testing.T) {
	uid, gid := requireBwrap(t)
	baseDir, err := os.MkdirTemp("", "bwrap-test-*")
	require.NoError(t, err)
	defer os.RemoveAll(baseDir)
	require.NoError(t, os.Chmod(baseDir, 0755))
	workDir := filepath.Join(baseDir, "work")
	require.NoError(t, os.MkdirAll(workDir, 0755))
	require.NoError(t, os.Chown(workDir, int(uid), int(gid)))

	// Empty cmd.Dir must chdir to the sandbox's private /tmp.
	emptyDirCmd := exec.Command("pwd")
	require.NoError(t, Wrap(emptyDirCmd))
	out, err := emptyDirCmd.CombinedOutput()
	require.NoError(t, err, "output: %s", out)
	assert.Equal(t, "/tmp", strings.TrimSpace(string(out)))

	// Non-existent explicit mounts must fail fast rather than being silently skipped.
	missingROCmd := exec.Command("true")
	missingROCmd.Dir = workDir
	assert.Error(t, Wrap(missingROCmd, WithReadOnly(filepath.Join(baseDir, "missing"))))

	etcLink := filepath.Join(baseDir, "etc-link")
	require.NoError(t, os.Symlink("/etc", etcLink))
	for _, badDir := range []string{"/", "/tmp", "/var/tmp", "/var/tmp/sub", "/home/syzkaller", "/etc", etcLink} {
		bad := exec.Command("true")
		bad.Dir = badDir
		assert.Error(t, Wrap(bad), "expected cmd.Dir=%q to be rejected", badDir)
	}
	for _, badRO := range []string{"/var/tmp", "/home/syzkaller", etcLink, filepath.Join(etcLink, "passwd")} {
		bad := exec.Command("true")
		bad.Dir = workDir
		assert.Error(t, Wrap(bad, WithReadOnly(badRO)), "expected RO mount %q to be rejected", badRO)
	}

	// If cmd.Dir traverses a host symlink, an executable inside cmd.Dir referenced via the
	// symlinked path must have its mount prefix rewritten without following inner symlinks.
	workLink := filepath.Join(baseDir, "work-link")
	require.NoError(t, os.Symlink(workDir, workLink))
	scriptsDir := filepath.Join(workDir, "scripts")
	require.NoError(t, os.MkdirAll(scriptsDir, 0755))
	okScript := filepath.Join(scriptsDir, "ok.sh")
	require.NoError(t, os.WriteFile(okScript, []byte("#!/bin/sh\necho symlink-dir-ok\n"), 0755))
	outsideScript := filepath.Join(baseDir, "outside.sh")
	require.NoError(t, os.WriteFile(outsideScript, []byte("#!/bin/sh\necho escaped\n"), 0755))
	escapeScript := filepath.Join(scriptsDir, "escape.sh")
	require.NoError(t, os.Symlink(outsideScript, escapeScript))

	linkOkCmd := exec.Command(filepath.Join(workLink, "scripts", "ok.sh"))
	linkOkCmd.Dir = workLink
	require.NoError(t, Wrap(linkOkCmd))
	out, err = linkOkCmd.CombinedOutput()
	require.NoError(t, err, "output: %s", out)
	assert.Equal(t, "symlink-dir-ok", strings.TrimSpace(string(out)))

	linkEscapeCmd := exec.Command(filepath.Join(workLink, "scripts", "escape.sh"))
	linkEscapeCmd.Dir = workLink
	require.NoError(t, Wrap(linkEscapeCmd))
	out, err = linkEscapeCmd.CombinedOutput()
	require.Error(t, err, "inner symlink escaping cmd.Dir must not be mounted: %s", out)
	assert.NotContains(t, string(out), "escaped")

	directEnvCmd := exec.Command("true")
	directEnvCmd.Dir = workDir
	directEnvCmd.Env = []string{"FOO=bar"}
	assert.Error(t, Wrap(directEnvCmd))

	badEnvCmd := exec.Command("true")
	badEnvCmd.Dir = workDir
	assert.Error(t, Wrap(badEnvCmd, WithEnv("NO_EQUALS")))

	roWorkCmd := exec.Command("sh", "-c", "touch should-fail")
	roWorkCmd.Dir = workDir
	require.NoError(t, Wrap(roWorkCmd))
	out, err = roWorkCmd.CombinedOutput()
	require.Error(t, err, "cmd.Dir must be read-only by default: %s", out)
	assert.NoFileExists(t, filepath.Join(workDir, "should-fail"))
}

func requireBwrap(t *testing.T) (uint32, uint32) {
	t.Helper()
	var err error
	if syscall.Getuid() != 0 {
		err = errors.New("requires root")
	} else {
		err = Available()
	}
	if err != nil {
		if os.Getenv("CI") != "" {
			t.Fatalf("bwrap tests must run on CI: %v", err)
		}
		t.Skipf("skipping bwrap test: %v", err)
	}
	uid, gid, err := SandboxUser()
	require.NoError(t, err)
	return uid, gid
}
