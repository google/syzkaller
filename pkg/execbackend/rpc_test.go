// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package execbackend

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

func TestRPCBackendLocal(t *testing.T) {
	target, err := prog.GetTarget(targets.TestOS, targets.TestArch64)
	require.NoError(t, err)

	executorBin := csource.BuildExecutor(t, target, "../..")

	p, err := target.Deserialize([]byte("syz_test_fuzzer1(0, 0, 0)"), prog.Strict)
	require.NoError(t, err)

	done := make(chan *queue.Result)
	req := &queue.Request{
		Prog: p,
		ExecOpts: flatrpc.ExecOpts{
			EnvFlags: flatrpc.ExecEnvSandboxNone,
		},
		ReturnOutput: true,
	}
	req.OnDone(func(r *queue.Request, res *queue.Result) bool {
		done <- res
		return true
	})

	q := queue.Plain()
	q.Submit(req)

	cfg := LocalConfig{
		Target:      target,
		ExecutorBin: executorBin,
		Dir:         t.TempDir(),
		Source:      q,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	go func() {
		select {
		case res := <-done:
			t.Logf("got execution result: status=%v output=%q", res.Status, res.Output)
			cancel() // successfully executed, stop the backend
		case <-ctx.Done():
		}
	}()

	reps, err := RunLocal(ctx, cfg)

	if err != nil && err != context.Canceled {
		t.Fatalf("unexpected error: %v", err)
	}

	t.Logf("reps: %v, err: %v", reps, err)
}
