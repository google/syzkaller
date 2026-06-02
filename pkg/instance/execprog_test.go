// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package instance

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/sys/targets"
	"github.com/google/syzkaller/vm"
	"github.com/google/syzkaller/vm/vmimpl"
	"github.com/stretchr/testify/require"
)

type mockInstance struct {
	runFunc func(ctx context.Context, command string) (<-chan vmimpl.Chunk, <-chan error, error)
}

func (m *mockInstance) Copy(hostSrc string) (string, error) {
	return "/tmp/" + filepath.Base(hostSrc), nil
}

func (m *mockInstance) Forward(port int) (string, error) {
	return "localhost:1234", nil
}

func (m *mockInstance) Run(ctx context.Context, command string) (<-chan vmimpl.Chunk, <-chan error, error) {
	if m.runFunc != nil {
		return m.runFunc(ctx, command)
	}
	return nil, nil, nil
}

func (m *mockInstance) Diagnose(rep *report.Report) ([]byte, bool) {
	return nil, false
}

func (m *mockInstance) Close() error {
	return nil
}

type mockPool struct {
	inst *mockInstance
}

func (p *mockPool) Count() int { return 1 }

func (p *mockPool) Create(ctx context.Context, workdir string, index int) (vmimpl.Instance, error) {
	return p.inst, nil
}

var globalMockPool = &mockPool{inst: &mockInstance{}}

func init() {
	vmimpl.Register("mock-vm", vmimpl.Type{
		Ctor: func(env *vmimpl.Env) (vmimpl.Pool, error) {
			return globalMockPool, nil
		},
	})
}

func TestRunStreamAndCollectStdout_Success(t *testing.T) {
	vmInst, _ := setupTestVM(t)
	defer func() { globalMockPool.inst.runFunc = nil }()

	globalMockPool.inst.runFunc = func(ctx context.Context, command string) (<-chan vmimpl.Chunk, <-chan error, error) {
		outc := make(chan vmimpl.Chunk, 4)
		errc := make(chan error, 1)
		outc <- vmimpl.Chunk{Data: []byte("console data"), Type: vmimpl.OutputConsole}
		outc <- vmimpl.Chunk{Data: []byte("hello"), Type: vmimpl.OutputStdout}
		outc <- vmimpl.Chunk{Data: []byte("stderr data"), Type: vmimpl.OutputStderr}
		outc <- vmimpl.Chunk{Data: []byte(" world"), Type: vmimpl.OutputStdout}
		close(outc)
		errc <- nil
		close(errc)
		return outc, errc, nil
	}

	var buf bytes.Buffer
	err := runStreamAndCollectStdout(t.Context(), vmInst, "cmd", &buf)
	require.NoError(t, err)
	require.Equal(t, "hello world", buf.String())
}

func TestRunStreamAndCollectStdout_WriteError(t *testing.T) {
	vmInst, _ := setupTestVM(t)
	defer func() { globalMockPool.inst.runFunc = nil }()

	ctxCancelled := make(chan struct{})
	globalMockPool.inst.runFunc = func(ctx context.Context, command string) (<-chan vmimpl.Chunk, <-chan error, error) {
		outc := make(chan vmimpl.Chunk)
		errc := make(chan error, 1)

		go func() {
			defer close(outc)
			defer close(errc)

			select {
			case outc <- vmimpl.Chunk{Data: []byte("hello"), Type: vmimpl.OutputStdout}:
			case <-ctx.Done():
				close(ctxCancelled)
				return
			}

			select {
			case <-ctx.Done():
				close(ctxCancelled)
				return
			case <-time.After(5 * time.Second):
			}
		}()

		return outc, errc, nil
	}

	writeErr := errors.New("write error")
	writer := &errorWriter{err: writeErr}

	err := runStreamAndCollectStdout(t.Context(), vmInst, "cmd", writer)
	require.ErrorIs(t, err, writeErr)

	// Verify that the VM context was cancelled.
	select {
	case <-ctxCancelled:
		// Success.
	case <-time.After(5 * time.Second):
		t.Fatal("VM run context was not cancelled on write error")
	}
}

func TestRunStreamAndCollectStdout_ContextCancelled(t *testing.T) {
	vmInst, _ := setupTestVM(t)
	defer func() { globalMockPool.inst.runFunc = nil }()

	ctxCancelled := make(chan struct{})
	globalMockPool.inst.runFunc = func(ctx context.Context, command string) (<-chan vmimpl.Chunk, <-chan error, error) {
		outc := make(chan vmimpl.Chunk)
		errc := make(chan error, 1)

		go func() {
			defer close(outc)
			defer close(errc)

			select {
			case <-ctx.Done():
				close(ctxCancelled)
				return
			case <-time.After(5 * time.Second):
			}
		}()

		return outc, errc, nil
	}

	ctx, cancel := context.WithCancel(t.Context())
	cancel() // Cancel immediately.

	var buf bytes.Buffer
	err := runStreamAndCollectStdout(ctx, vmInst, "cmd", &buf)
	require.ErrorIs(t, err, context.Canceled)

	// Verify that the VM context was cancelled.
	select {
	case <-ctxCancelled:
		// Success.
	case <-time.After(5 * time.Second):
		t.Fatal("VM run context was not cancelled when parent context was cancelled")
	}
}

func TestRunStreamAndCollectStdout_CommandError(t *testing.T) {
	vmInst, _ := setupTestVM(t)
	defer func() { globalMockPool.inst.runFunc = nil }()

	cmdErr := errors.New("command failed")
	globalMockPool.inst.runFunc = func(ctx context.Context, command string) (<-chan vmimpl.Chunk, <-chan error, error) {
		outc := make(chan vmimpl.Chunk, 1)
		errc := make(chan error, 1)
		outc <- vmimpl.Chunk{Data: []byte("hello"), Type: vmimpl.OutputStdout}
		close(outc)
		errc <- cmdErr
		close(errc)
		return outc, errc, nil
	}

	var buf bytes.Buffer
	err := runStreamAndCollectStdout(t.Context(), vmInst, "cmd", &buf)
	require.ErrorIs(t, err, cmdErr)
	require.Equal(t, "hello", buf.String())
}

func TestRunStreamAndCollectStdout_CommandErrorUnclosedErrc(t *testing.T) {
	vmInst, _ := setupTestVM(t)
	defer func() { globalMockPool.inst.runFunc = nil }()

	cmdErr := errors.New("command failed")
	globalMockPool.inst.runFunc = func(ctx context.Context, command string) (<-chan vmimpl.Chunk, <-chan error, error) {
		outc := make(chan vmimpl.Chunk, 1)
		errc := make(chan error, 1)
		outc <- vmimpl.Chunk{Data: []byte("hello"), Type: vmimpl.OutputStdout}
		close(outc)
		errc <- cmdErr
		return outc, errc, nil
	}

	var buf bytes.Buffer
	ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer cancel()

	err := runStreamAndCollectStdout(ctx, vmInst, "cmd", &buf)
	require.ErrorIs(t, err, cmdErr)
	require.Equal(t, "hello", buf.String())
}

func setupTestVM(t *testing.T) (*vm.Instance, *mgrconfig.Config) {
	cfg := &mgrconfig.Config{
		Derived: mgrconfig.Derived{
			TargetOS:     targets.Linux,
			TargetArch:   targets.AMD64,
			TargetVMArch: targets.AMD64,
			SysTarget:    targets.Get(targets.Linux, targets.AMD64),
			Timeouts: targets.Timeouts{
				Scale: 1,
			},
		},
		Type:    "mock-vm",
		Workdir: t.TempDir(),
	}
	pool, err := vm.Create(cfg, false)
	require.NoError(t, err)

	vmInst, err := pool.Create(t.Context(), 0)
	require.NoError(t, err)

	return vmInst, cfg
}

type errorWriter struct {
	err error
}

func (w *errorWriter) Write(p []byte) (n int, err error) {
	return 0, w.err
}
