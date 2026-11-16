// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package qemu

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestQMPUnixSocket(t *testing.T) {
	wd, err := os.Getwd()
	require.NoError(t, err)
	if shortPath := filepath.Join(wd, "sub", "qmp.sock"); len(shortPath) <= maxUnixSockPath {
		assert.Equal(t, shortPath, unixSockPath(filepath.Join(wd, "sub"), "qmp.sock"))
	}
	longSub := strings.Repeat("a", maxUnixSockPath)
	assert.Equal(t, filepath.Join(longSub, "qmp.sock"), unixSockPath(filepath.Join(wd, longSub), "qmp.sock"))

	workdir := filepath.Join(t.TempDir(), "instance,0")
	require.NoError(t, os.Mkdir(workdir, 0700))

	sockPath := unixSockPath(workdir, "qmp.sock")
	inst := &instance{
		cfg:        &Config{CPU: 1, Mem: 1024, NetDev: "e1000"},
		archConfig: archConfigs["linux/amd64"],
		workdir:    workdir,
		monSock:    sockPath,
	}
	args, err := inst.buildQemuArgs()
	require.NoError(t, err)
	// The comma in the workdir name must be escaped as ",,".
	prefix := strings.TrimSuffix(sockPath, filepath.Join("instance,0", "qmp.sock"))
	assert.Contains(t, args, "socket,id=SOCKSYZ,server=on,wait=off,path="+
		prefix+filepath.Join("instance,,0", "qmp.sock"))

	ln, err := net.Listen("unix", sockPath)
	require.NoError(t, err)
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if !assert.NoError(t, err) {
			return
		}
		defer func() { assert.NoError(t, conn.Close()) }()
		enc, dec := json.NewEncoder(conn), json.NewDecoder(conn)
		var cmd qmpCommand
		assert.NoError(t, enc.Encode(map[string]any{"QMP": map[string]any{}}))
		assert.NoError(t, dec.Decode(&cmd))
		assert.NoError(t, enc.Encode(map[string]any{"return": map[string]any{}}))
		assert.NoError(t, dec.Decode(&cmd))
		assert.NoError(t, enc.Encode(map[string]any{"return": "RAX=0000000000000001\n"}))
	}()
	t.Cleanup(func() {
		require.NoError(t, inst.Close())
		require.NoError(t, ln.Close())
		<-done
	})

	regs, err := inst.hmp("info registers", 0)
	require.NoError(t, err)
	assert.Equal(t, "RAX=0000000000000001\n", regs)
}

func TestEscapeQemuOpt(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"/tmp/qmp.sock", "/tmp/qmp.sock"},
		{"/tmp/a,b/qmp.sock", "/tmp/a,,b/qmp.sock"},
		{"a,,b", "a,,,,b"},
		{",a,", ",,a,,"},
	}
	for _, test := range tests {
		assert.Equal(t, test.want, escapeQemuOpt(test.in), "input: %q", test.in)
	}
}
