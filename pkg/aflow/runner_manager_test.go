// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/pkg/vminfo"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
	"github.com/google/syzkaller/vm"
	"github.com/google/syzkaller/vm/dispatcher"
	"github.com/stretchr/testify/require"
)

type mockExecBackend struct {
	source  queue.Source
	reports []*report.Report
	err     error
}

func (m *mockExecBackend) Setup() error                             { return nil }
func (m *mockExecBackend) Serve(ctx context.Context) error          { return nil }
func (m *mockExecBackend) Close() error                             { return nil }
func (m *mockExecBackend) TriagedCorpus()                           {}
func (m *mockExecBackend) DistributeSignalDelta(plus signal.Signal) {}
func (m *mockExecBackend) SetSource(source queue.Source)            { m.source = source }
func (m *mockExecBackend) Features() flatrpc.Feature                { return 0 }

func (m *mockExecBackend) RunRequests(ctx context.Context, inst *vm.Instance, reporter *report.Reporter,
	updInfo dispatcher.UpdateInfo) ([]*report.Report, error) {
	return m.reports, m.err
}

func createTestMgrConfig() *mgrconfig.Config {
	target, _ := prog.GetTarget("linux", "amd64")
	sysTarget := targets.Get("linux", "amd64")
	return &mgrconfig.Config{
		RawTarget: "linux/amd64",
		Sandbox:   "none",
		Derived: mgrconfig.Derived{
			Target:       target,
			SysTarget:    sysTarget,
			TargetOS:     "linux",
			TargetArch:   "amd64",
			TargetVMArch: "amd64",
			Timeouts:     sysTarget.Timeouts(1),
		},
	}
}

func TestRunnerManager_Basic(t *testing.T) {
	ctx := context.Background()
	cfg := createTestMgrConfig()

	rm, err := newRunnerManager(ctx, cfg, false)
	require.NoError(t, err)
	require.NotNil(t, rm)
	require.Equal(t, cfg, rm.Config())

	// Test methods returning default/empty structures.
	filter, err := rm.CoverageFilter([]*vminfo.KernelModule{})
	require.NoError(t, err)
	require.Empty(t, filter)

	require.Nil(t, rm.MaxSignal())

	leaks, races := rm.BugFrames()
	require.Nil(t, leaks)
	require.Nil(t, races)

	require.Empty(t, rm.RecentCrashes())
}

func TestRunnerManager_New_Error(t *testing.T) {
	ctx := context.Background()
	// Invalid config with no target will cause report.NewReporter to fail.
	invalidCfg := &mgrconfig.Config{}
	rm, err := newRunnerManager(ctx, invalidCfg, false)
	require.Error(t, err)
	require.Nil(t, rm)
}

func TestRunnerManager_Submit_Empty(t *testing.T) {
	ctx := context.Background()
	cfg := createTestMgrConfig()

	rm, err := newRunnerManager(ctx, cfg, false)
	require.NoError(t, err)

	res, err := rm.SubmitBatch(ctx, nil)
	require.NoError(t, err)
	require.Nil(t, res)

	res, err = rm.SubmitBatch(ctx, []*prog.Prog{})
	require.NoError(t, err)
	require.Nil(t, res)
}

func TestRunnerManager_Submit_Canceled(t *testing.T) {
	target, err := prog.GetTarget("linux", "amd64")
	require.NoError(t, err)
	p, err := target.Deserialize([]byte("getpid()"), prog.NonStrict)
	require.NoError(t, err)

	cfg := createTestMgrConfig()

	// 1. Caller context canceled
	rmCtx, rmCancel := context.WithCancel(t.Context())
	defer rmCancel()
	rm, err := newRunnerManager(rmCtx, cfg, false)
	require.NoError(t, err)

	canceledCtx, cancel := context.WithCancel(t.Context())
	cancel()

	_, err = rm.Submit(canceledCtx, p)
	require.ErrorIs(t, err, context.Canceled)

	// 2. RunnerManager internal context canceled
	rmCtx2, rmCancel2 := context.WithCancel(t.Context())
	rmCancel2()
	rm2, err := newRunnerManager(rmCtx2, cfg, false)
	require.NoError(t, err)

	_, err = rm2.SubmitBatch(t.Context(), []*prog.Prog{p})
	require.ErrorIs(t, err, context.Canceled)
}

func TestRunnerManager_Submit_Success(t *testing.T) {
	target, err := prog.GetTarget("linux", "amd64")
	require.NoError(t, err)
	p1, err := target.Deserialize([]byte("getpid()"), prog.NonStrict)
	require.NoError(t, err)
	p2, err := target.Deserialize([]byte("getuid()"), prog.NonStrict)
	require.NoError(t, err)

	cfg := createTestMgrConfig()
	rm, err := newRunnerManager(context.Background(), cfg, false)
	require.NoError(t, err)

	// Background worker simulating syz-executor completing requests from rm.source.
	go func() {
		for {
			req := rm.source.Next()
			if req == nil {
				time.Sleep(5 * time.Millisecond)
				continue
			}
			req.Done(&queue.Result{
				Info: &flatrpc.ProgInfo{
					Calls: []*flatrpc.CallInfo{
						{Cover: []uint64{0x1000}},
					},
				},
			})
		}
	}()

	// 1. Single Submit
	res, err := rm.Submit(context.Background(), p1)
	require.NoError(t, err)
	require.NotNil(t, res)
	require.NotNil(t, res.Info)

	// 2. SubmitBatch
	batchRes, err := rm.SubmitBatch(context.Background(), []*prog.Prog{p1, p2})
	require.NoError(t, err)
	require.Len(t, batchRes, 2)
	require.NotNil(t, batchRes[0].Info)
	require.NotNil(t, batchRes[1].Info)

	// 3. SubmitAsync
	asyncDone := make(chan *queue.Result, 1)
	rm.SubmitAsync(p1, func(res *queue.Result) {
		asyncDone <- res
	})
	select {
	case asyncRes := <-asyncDone:
		require.NotNil(t, asyncRes)
		require.NotNil(t, asyncRes.Info)
	case <-time.After(5 * time.Second):
		t.Fatal("SubmitAsync timed out waiting for completion")
	}
}

func TestRunnerManager_MachineChecked(t *testing.T) {
	target, err := prog.GetTarget("linux", "amd64")
	require.NoError(t, err)
	cfg := createTestMgrConfig()
	rm, err := newRunnerManager(context.Background(), cfg, false)
	require.NoError(t, err)

	mockBackend := &mockExecBackend{}
	rm.backend = mockBackend

	// 1. Empty syscalls returns error
	err = rm.MachineChecked(0, nil)
	require.EqualError(t, err, "no syscalls enabled for runner")

	// 2. Non-empty syscalls succeeds and closes readyC
	enabledSyscalls := map[*prog.Syscall]bool{
		target.SyscallMap["getpid"]: true,
	}
	err = rm.MachineChecked(flatrpc.FeatureCoverage, enabledSyscalls)
	require.NoError(t, err)
	require.NotNil(t, mockBackend.source)

	select {
	case <-rm.readyC:
	default:
		t.Fatal("readyC was not closed after MachineChecked")
	}

	// 3. Subsequent MachineChecked call does not panic
	err = rm.MachineChecked(flatrpc.FeatureCoverage, enabledSyscalls)
	require.NoError(t, err)
}

func TestRunnerManager_ExecutorInstance(t *testing.T) {
	cfg := createTestMgrConfig()
	rm, err := newRunnerManager(context.Background(), cfg, false)
	require.NoError(t, err)

	mockBackend := &mockExecBackend{
		reports: []*report.Report{
			{Title: "kernel BUG in test_func", Report: []byte("stack trace")},
		},
		err: errors.New("instance crashed"),
	}
	rm.backend = mockBackend

	rm.executorInstance(context.Background(), nil, nil)

	crashes := rm.RecentCrashes()
	require.Len(t, crashes, 1)
	require.Equal(t, "kernel BUG in test_func", crashes[0].Title)

	// Verify RecentCrashes returns a copy.
	crashes[0] = nil
	require.NotNil(t, rm.RecentCrashes()[0])
}

func TestRunIsolatedManager_InvalidConfig(t *testing.T) {
	invalidCfg := &mgrconfig.Config{}
	err := RunIsolatedManager(context.Background(), invalidCfg, false, func(ctx context.Context, rm *RunnerManager) error {
		return nil
	})
	require.ErrorContains(t, err, "failed to create isolated RunnerManager")
}

func TestRunIsolatedManager_LoopFailure(t *testing.T) {
	cfg := createTestMgrConfig()
	// Invalid VM type causes vm.Create inside rm.Loop to fail immediately.
	cfg.Type = "invalid_vm_type"
	err := RunIsolatedManager(context.Background(), cfg, false, func(ctx context.Context, rm *RunnerManager) error {
		return nil
	})
	require.ErrorContains(t, err, "isolated RunnerManager loop failed")
}

func TestRunIsolatedManager_ContextCanceled(t *testing.T) {
	cfg := createTestMgrConfig()
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	err := RunIsolatedManager(ctx, cfg, false, func(ctx context.Context, rm *RunnerManager) error {
		return nil
	})
	require.ErrorIs(t, err, context.Canceled)
}
