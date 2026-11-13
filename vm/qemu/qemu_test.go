// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package qemu

import (
	"context"
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/syzkaller/vm/vmimpl"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestQMPUnixSocket(t *testing.T) {
	wd, err := os.Getwd()
	require.NoError(t, err)
	assert.Equal(t, filepath.Join("sub", "qmp.sock"), unixSockPath(filepath.Join(wd, "sub"), "qmp.sock"))

	workdir := filepath.Join(t.TempDir(), "instance,0")
	require.NoError(t, os.Mkdir(workdir, 0755))
	require.NoError(t, os.Chmod(workdir, 0755))

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err = (&Pool{env: &vmimpl.Env{}}).Create(ctx, workdir, 0)
	require.ErrorIs(t, err, context.Canceled)
	info, err := os.Stat(workdir)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0700), info.Mode().Perm())

	sockPath := unixSockPath(workdir, "qmp.sock")
	inst := &instance{
		cfg:        &Config{CPU: 1, Mem: 1024, NetDev: "e1000"},
		archConfig: archConfigs["linux/amd64"],
		workdir:    workdir,
		monSock:    sockPath,
	}
	args, err := inst.buildQemuArgs()
	require.NoError(t, err)
	assert.Contains(t, args, "socket,id=SOCKSYZ,server=on,wait=off,path="+escapeQemuOpt(sockPath))

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
