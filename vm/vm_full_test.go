// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vm

import (
	"context"
	"io"
	"strings"
	"testing"

	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/vm/vmimpl"
	"github.com/stretchr/testify/assert"
)

type localInstancePool struct {
}

func (pool *localInstancePool) Count() int {
	return 1
}

func (pool *localInstancePool) Create(_ context.Context, workdir string, index int) (vmimpl.Instance, error) {
	return makeLocalInstance(workdir), nil
}

func (pool *localInstancePool) Close() error {
	return nil
}

type localInstance struct {
	merger  *vmimpl.OutputMerger
	workdir string
}

func makeLocalInstance(workdir string) *localInstance {
	var tee io.Writer
	// TODO: tee to t.Logf.
	return &localInstance{
		merger:  vmimpl.NewOutputMerger(tee),
		workdir: workdir,
	}
}

func (inst *localInstance) Copy(hostSrc string) (string, error) {
	return "", nil
}

func (inst *localInstance) Forward(port int) (string, error) {
	return "", nil
}

func (inst *localInstance) Run(ctx context.Context, command string) (
	<-chan vmimpl.Chunk, <-chan error, error) {
	rpipe, wpipe, err := osutil.LongPipe()
	if err != nil {
		return nil, nil, err
	}
	rpipeErr, wpipeErr, err := osutil.LongPipe()
	if err != nil {
		rpipe.Close()
		wpipe.Close()
		return nil, nil, err
	}
	inst.merger.Add("ssh", vmimpl.OutputStdout, rpipe)
	inst.merger.Add("ssh-err", vmimpl.OutputStderr, rpipeErr)
	args := strings.Split(command, " ")
	cmd := osutil.Command(args[0], args[1:]...)
	cmd.Dir = inst.workdir
	cmd.Stdout = wpipe
	cmd.Stderr = wpipeErr
	if err := cmd.Start(); err != nil {
		wpipe.Close()
		wpipeErr.Close()
		return nil, nil, err
	}
	wpipe.Close()
	wpipeErr.Close()
	return vmimpl.Multiplex(ctx, cmd, inst.merger, vmimpl.MultiplexConfig{
		Scale: 1,
	})
}

func (inst *localInstance) Diagnose(rep *report.Report) ([]byte, bool) {
	return nil, false
}

func (inst *localInstance) Close() error {
	inst.merger.Wait()
	return nil
}

func init() {
	ctor := func(env *vmimpl.Env) (vmimpl.Pool, error) {
		return &localInstancePool{}, nil
	}
	vmimpl.Register("test-local", vmimpl.Type{
		Ctor:        ctor,
		Preemptible: true,
	})
}

func TestMultipleRun(t *testing.T) {
	inst, reporter := makeLinuxAMD64Futex(t, "test-local")
	for i := 0; i < 3; i++ {
		output, _, err := inst.Run(context.Background(), reporter,
			`echo Hello`, WithExitCondition(ExitNormal))
		assert.NoError(t, err)
		assert.Equal(t, "Hello\n", string(output))
	}
}
