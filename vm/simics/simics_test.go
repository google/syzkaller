// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package simics

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/sys/targets"
	"github.com/google/syzkaller/vm/vmimpl"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testGuestIP = "10.10.0.100"

// forwardLine returns the line Simics prints for a host port forwarded to the guest port.
func forwardLine(hostPort, guestPort int) string {
	return fmt.Sprintf("Host TCP port %v -> %v:%v", hostPort, testGuestIP, guestPort)
}

// fakeProject creates a Simics project directory with a dummy launcher and kernel.
func fakeProject(t *testing.T) (project, kernel string) {
	dir := t.TempDir()
	project = filepath.Join(dir, "project")
	require.NoError(t, os.Mkdir(project, 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(project, "simics"), []byte("#!/bin/sh\n"), 0o755))
	kernel = filepath.Join(dir, "bzImage")
	require.NoError(t, os.WriteFile(kernel, []byte("kernel"), 0o644))
	return project, kernel
}

func TestCtor(t *testing.T) {
	project, kernel := fakeProject(t)
	missing := filepath.Join(t.TempDir(), "missing")
	tests := []struct {
		name    string
		cfg     string
		image   string
		env     string
		wantErr string
		check   func(t *testing.T, pool *Pool)
	}{
		{
			name:  "defaults",
			cfg:   fmt.Sprintf(`{"project": %q, "kernel": %q}`, project, kernel),
			image: "/image",
			check: func(t *testing.T, pool *Pool) {
				assert.Equal(t, 1, pool.Count())
				assert.Equal(t, filepath.Join(project, "simics"), pool.cfg.Simics)
				assert.Equal(t, defaultTarget, pool.cfg.Target)
				assert.Equal(t, defaultArgs, pool.cfg.SimicsArgs)
				assert.Equal(t, defaultGuestIP, pool.cfg.GuestIP)
				assert.Equal(t, defaultBootTimeout, pool.cfg.BootTimeout)
				assert.True(t, pool.cfg.ConsoleLog)
				assert.Equal(t, defaultParams, pool.params)
			},
		},
		{
			name:  "project from env",
			cfg:   fmt.Sprintf(`{"kernel": %q, "count": 3}`, kernel),
			image: "/image",
			env:   project,
			check: func(t *testing.T, pool *Pool) {
				assert.Equal(t, 3, pool.Count())
				assert.Equal(t, project, pool.cfg.Project)
			},
		},
		{
			name: "custom target has no preset params",
			cfg: fmt.Sprintf(`{"project": %q, "target": "targets/x.simics", "params": {"a": "b"}}`,
				project),
			check: func(t *testing.T, pool *Pool) {
				assert.Equal(t, map[string]string{"a": "b"}, pool.params)
			},
		},
		{
			name: "params override defaults",
			cfg: fmt.Sprintf(`{"project": %q, "kernel": %q, "params": {"machine:software:linux:cmdline": "x"}}`,
				project, kernel),
			image: "/image",
			check: func(t *testing.T, pool *Pool) {
				assert.Equal(t, "x", pool.params["machine:software:linux:cmdline"])
				assert.Equal(t, "{{KERNEL}}", pool.params["machine:software:linux:kernel"])
			},
		},
		{
			name:    "bad json",
			cfg:     `{"project": 1}`,
			wantErr: "failed to parse simics vm config",
		},
		{
			name:    "unknown field",
			cfg:     fmt.Sprintf(`{"project": %q, "bogus": 1}`, project),
			wantErr: "failed to parse simics vm config",
		},
		{
			name:    "count too small",
			cfg:     fmt.Sprintf(`{"project": %q, "count": 0}`, project),
			wantErr: "invalid config param count",
		},
		{
			name:    "count too large",
			cfg:     fmt.Sprintf(`{"project": %q, "count": 129}`, project),
			wantErr: "invalid config param count",
		},
		{
			name:    "bad boot timeout",
			cfg:     fmt.Sprintf(`{"project": %q, "boot_timeout": -1}`, project),
			wantErr: "invalid config param boot_timeout",
		},
		{
			name:    "bad guest ip",
			cfg:     fmt.Sprintf(`{"project": %q, "guest_ip": "not-an-ip"}`, project),
			wantErr: "invalid config param guest_ip",
		},
		{
			name:    "no project",
			cfg:     `{}`,
			wantErr: "config param project is not set",
		},
		{
			name:    "missing project",
			cfg:     fmt.Sprintf(`{"project": %q}`, missing),
			wantErr: "does not exist",
		},
		{
			name:    "missing launcher",
			cfg:     fmt.Sprintf(`{"project": %q, "simics": %q}`, project, missing),
			wantErr: "simics launcher",
		},
		{
			name:    "missing kernel",
			cfg:     fmt.Sprintf(`{"project": %q, "kernel": %q}`, project, missing),
			wantErr: "kernel",
		},
		{
			name:    "default target needs kernel",
			cfg:     fmt.Sprintf(`{"project": %q}`, project),
			image:   "/image",
			wantErr: "needs the kernel config param",
		},
		{
			name:    "default target needs image",
			cfg:     fmt.Sprintf(`{"project": %q, "kernel": %q}`, project, kernel),
			wantErr: "needs the manager image",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv("SIMICS_PROJECT", test.env)
			env := &vmimpl.Env{Config: []byte(test.cfg), Image: test.image}
			pool, err := ctor(env)
			if test.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), test.wantErr)
				return
			}
			require.NoError(t, err)
			test.check(t, pool.(*Pool))
		})
	}
}

func TestSimicsArgs(t *testing.T) {
	pool := &Pool{
		env: &vmimpl.Env{Image: "/img"},
		cfg: &Config{
			SimicsArgs: "--no-win  --batch-mode",
			Target:     "tgt",
			Kernel:     "/k",
			Cmdline:    "console=ttyS0",
			Commands:   []string{"echo {{INDEX}}"},
		},
		params: map[string]string{
			"z": "{{KERNEL}}",
			"a": "{{IMAGE}} {{CMDLINE}}",
			"m": "{{WORKDIR}}/{{INDEX}}",
		},
	}
	inst := &instance{index: 7, workdir: "/wd"}
	got := pool.simicsArgs(inst, "/wd/setup.py")
	want := []string{
		"--no-win", "--batch-mode", "tgt",
		"a=/img console=ttyS0", "m=/wd/7", "z=/k",
		"-e", `run-script "/wd/setup.py"`,
		"-e", "echo 7",
		"-e", "run",
	}
	assert.Equal(t, want, got)
	// The order must be stable.
	for i := 0; i < 10; i++ {
		assert.Equal(t, want, pool.simicsArgs(inst, "/wd/setup.py"))
	}
}

func TestSetupScript(t *testing.T) {
	pool := &Pool{cfg: &Config{
		Console:      `con"; import os #`,
		EthernetLink: "link0",
		GuestIP:      testGuestIP,
	}}
	inst := &instance{consolePort: 4321}
	script := string(pool.setupScript(inst))
	m := regexp.MustCompile(`b64decode\('([^']*)'\)`).FindStringSubmatch(script)
	require.NotNil(t, m, "no encoded params in:\n%s", script)
	raw, err := base64.StdEncoding.DecodeString(m[1])
	require.NoError(t, err)
	var params map[string]any
	require.NoError(t, json.Unmarshal(raw, &params))
	assert.Equal(t, pool.cfg.Console, params["console"])
	assert.Equal(t, "link0", params["ethernet_link"])
	assert.Equal(t, testGuestIP, params["guest_ip"])
	assert.EqualValues(t, 4321, params["console_port"])
	assert.Greater(t, params["ssh_port"], float64(0))
	// The arbitrary config string must not leak into the script text.
	assert.NotContains(t, script, "import os #")
	// All format verbs must have been expanded.
	assert.NotContains(t, script, "%!")
	assert.Contains(t, script, "connect-real-network-port-in")
}

func TestParseSimicsLine(t *testing.T) {
	tests := []struct {
		line string
		port int
	}{
		{forwardLine(4022, 22), 4022},
		{"[ssh] " + forwardLine(65535, 22) + " forwarded", 65535},
		{forwardLine(4022, 2222), 0},
		{forwardLine(0, 22), 0},
		{forwardLine(70000, 22), 0},
		{"unrelated output", 0},
		{"", 0},
	}
	for _, test := range tests {
		t.Run(test.line, func(t *testing.T) {
			inst := &instance{sshPortc: make(chan int, 1)}
			inst.parseSimicsLine([]byte(test.line))
			select {
			case port := <-inst.sshPortc:
				assert.Equal(t, test.port, port)
			default:
				assert.Equal(t, 0, test.port, "no port reported")
			}
		})
	}
}

func TestParseSimicsLineDoesNotBlock(t *testing.T) {
	inst := &instance{sshPortc: make(chan int, 1)}
	inst.parseSimicsLine([]byte(forwardLine(1000, 22)))
	inst.parseSimicsLine([]byte(forwardLine(2000, 22)))
	assert.Equal(t, 1000, <-inst.sshPortc)
	assert.Empty(t, inst.sshPortc)
}

type nopReadCloser struct {
	io.Reader
	closed bool
}

func (n *nopReadCloser) Close() error {
	n.closed = true
	return nil
}

func TestLineWatcher(t *testing.T) {
	var lines []string
	src := &nopReadCloser{Reader: strings.NewReader("one\r\ntwo\npartial")}
	w := &lineWatcher{r: src, onLine: func(line []byte) { lines = append(lines, string(line)) }}
	data, err := io.ReadAll(w)
	require.NoError(t, err)
	assert.Equal(t, "one\r\ntwo\npartial", string(data))
	assert.Equal(t, []string{"one", "two"}, lines)
	require.NoError(t, w.Close())
	assert.True(t, src.closed)
}

func TestLineWatcherSplitAndLong(t *testing.T) {
	var lines []string
	// Reads that split a line in the middle.
	src := io.MultiReader(strings.NewReader("ab"), strings.NewReader("c\nd"), strings.NewReader("e\n"))
	w := &lineWatcher{r: &nopReadCloser{Reader: src}, onLine: func(line []byte) { lines = append(lines, string(line)) }}
	_, err := io.ReadAll(w)
	require.NoError(t, err)
	assert.Equal(t, []string{"abc", "de"}, lines)

	// A very long line without a newline must not grow the buffer unboundedly.
	long := strings.Repeat("x", 100<<10)
	w = &lineWatcher{r: &nopReadCloser{Reader: strings.NewReader(long)}, onLine: func([]byte) {}}
	_, err = io.ReadAll(w)
	require.NoError(t, err)
	assert.LessOrEqual(t, len(w.buf), 4<<10)
}

func TestTelnetFilter(t *testing.T) {
	tests := []struct {
		name string
		in   [][]byte
		want string
	}{
		{"plain", [][]byte{[]byte("hello\r\n")}, "hello\r\n"},
		{"nul dropped", [][]byte{[]byte("a\x00b")}, "ab"},
		{"escaped iac", [][]byte{{'a', 255, 255, 'b'}}, "a\xffb"},
		{"will option", [][]byte{{'a', 255, 251, 1, 'b'}}, "ab"},
		{"dont option", [][]byte{{255, 254, 3, 'x'}}, "x"},
		{"other command", [][]byte{{255, 241, 'x'}}, "x"},
		{"subnegotiation", [][]byte{{'a', 255, 250, 24, 1, 255, 240, 'b'}}, "ab"},
		{"subnegotiation with inner iac", [][]byte{{255, 250, 1, 255, 1, 2, 255, 240, 'z'}}, "z"},
		{"split across reads", [][]byte{{'a', 255}, {251}, {1, 'b', 255}, {255}}, "ab\xff"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tr := &telnetReader{}
			var out []byte
			for _, in := range test.in {
				out = tr.filter(out, in)
			}
			assert.Equal(t, test.want, string(out))
		})
	}
}

func TestTelnetReader(t *testing.T) {
	client, server := net.Pipe()
	tr := newTelnetReader(client)
	go func() {
		// The first write contains only a command, so Read must keep waiting for data.
		server.Write([]byte{255, 251, 1})
		server.Write([]byte("kernel log\n"))
		server.Close()
	}()
	data, err := io.ReadAll(tr)
	require.NoError(t, err)
	assert.Equal(t, "kernel log\n", string(data))
	require.NoError(t, tr.Close())
}

func TestTeeLog(t *testing.T) {
	src := &nopReadCloser{Reader: strings.NewReader("data")}
	inst := &instance{}
	// Without a log file the reader is returned as is.
	assert.Same(t, src, inst.teeLog(src))

	var buf bytes.Buffer
	tee := &teeReader{r: src, w: &buf}
	got, err := io.ReadAll(tee)
	require.NoError(t, err)
	assert.Equal(t, "data", string(got))
	assert.Equal(t, "data", buf.String())
	require.NoError(t, tee.Close())
	assert.True(t, src.closed)

	f, err := os.Create(filepath.Join(t.TempDir(), "log"))
	require.NoError(t, err)
	defer f.Close()
	inst.log = f
	_, ok := inst.teeLog(src).(*teeReader)
	assert.True(t, ok)
}

func TestForward(t *testing.T) {
	inst := &instance{}
	_, err := inst.Forward(0)
	assert.Error(t, err)
	addr, err := inst.Forward(1234)
	require.NoError(t, err)
	assert.Equal(t, "localhost:1234", addr)
	_, err = inst.Forward(1234)
	assert.Error(t, err)
}

func TestInfo(t *testing.T) {
	inst := &instance{cfg: &Config{Simics: "/p/simics"}, args: []string{"a", "b c"}}
	info, err := inst.Info()
	require.NoError(t, err)
	assert.Equal(t, "/p/simics [\"a\" \"b c\"]\n", string(info))
}

func TestCloseEmpty(t *testing.T) {
	// Close must be safe on an instance that failed before starting anything.
	require.NoError(t, (&instance{}).Close())
}

func TestConnectConsole(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()
	inst := &instance{consolePort: ln.Addr().(*net.TCPAddr).Port}
	conn, err := inst.connectConsole(time.Now().Add(10*time.Second), make(chan error))
	require.NoError(t, err)
	conn.Close()
}

func TestConnectConsoleSimicsExited(t *testing.T) {
	// A port nobody listens on.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	inst := &instance{consolePort: port}
	stop := make(chan error, 1)
	stop <- io.EOF
	_, err = inst.connectConsole(time.Now().Add(time.Minute), stop)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "simics exited")
}

func TestConnectConsoleTimeout(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	inst := &instance{consolePort: port}
	_, err = inst.connectConsole(time.Now().Add(50*time.Millisecond), make(chan error))
	require.Error(t, err)
	assert.Contains(t, err.Error(), "can't connect to the serial console")
}

func TestCreateCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	pool := &Pool{cfg: &Config{}, env: &vmimpl.Env{}}
	_, err := pool.Create(ctx, t.TempDir(), 0)
	assert.ErrorIs(t, err, context.Canceled)
}

func TestDiagnoseNonLinux(t *testing.T) {
	inst := &instance{os: targets.FreeBSD}
	out, wait := inst.Diagnose(&report.Report{})
	assert.Nil(t, out)
	assert.False(t, wait)
}
