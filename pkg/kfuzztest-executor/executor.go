// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

//go:build linux

// Package kfuzztestexecutor implements local execution (i.e., without the
// C++ executor program) for KFuzzTest targets.
package kfuzztestexecutor

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/kcov"
	"github.com/google/syzkaller/pkg/kfuzztest"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/prog"
)

// KFuzzTestExecutor is an executor that upon receiving a request, will invoke
// a KFuzzTest target.
type KFuzzTestExecutor struct {
	ctx     context.Context
	jobChan chan *queue.Request
	// Cooldown between execution requests.
	cooldown time.Duration
	wg       sync.WaitGroup
}

// Implements the queue.Executor interface.
func (kfe *KFuzzTestExecutor) Submit(req *queue.Request) {
	kfe.jobChan <- req
}

func (kfe *KFuzzTestExecutor) Shutdown() {
	close(kfe.jobChan)
	kfe.wg.Wait()
}

func NewKFuzzTestExecutor(ctx context.Context, numWorkers int, cooldown uint32) *KFuzzTestExecutor {
	jobChan := make(chan *queue.Request)

	kfe := &KFuzzTestExecutor{
		ctx:      ctx,
		jobChan:  jobChan,
		cooldown: time.Duration(cooldown) * time.Second,
	}

	kfe.wg.Add(numWorkers)
	for i := range numWorkers {
		go kfe.workerLoop(i)
	}
	return kfe
}

func (kfe *KFuzzTestExecutor) workerLoop(tid int) {
	defer kfe.wg.Done()
	kcovSt, err := kcov.EnableTracingForCurrentGoroutine()
	if err != nil {
		log.Logf(1, "failed to enable kcov for thread_%d", tid)
		return
	}
	defer kcovSt.DisableTracing()

	for req := range kfe.jobChan {
		if req.Prog == nil {
			log.Logf(1, "thread_%d: exec request had nil program", tid)
		}

		info := new(flatrpc.ProgInfo)
		for _, call := range req.Prog.Calls {
			callInfo := new(flatrpc.CallInfo)

			// Trace each individual call, collecting the covered PCs.
			coverage, err := execKFuzzTestCallLocal(kcovSt, call)
			if err != nil {
				// Set this call info as a failure. -1 is a placeholder.
				callInfo.Error = -1
				callInfo.Flags |= flatrpc.CallFlagBlocked
			} else {
				for _, pc := range coverage {
					callInfo.Signal = append(callInfo.Signal, uint64(pc))
					callInfo.Cover = append(callInfo.Cover, uint64(pc))
				}
				callInfo.Flags |= flatrpc.CallFlagExecuted
			}

			info.Calls = append(info.Calls, callInfo)
		}

		req.Done(&queue.Result{Info: info, Executor: queue.ExecutorID{VM: 0, Proc: tid}})

		if kfe.cooldown != 0 {
			time.Sleep(kfe.cooldown)
		}
	}
	log.Logf(0, "thread_%d exiting", tid)
}

func execKFuzzTestCallLocal(st *kcov.KCOVState, call *prog.Call) ([]uintptr, error) {
	if !call.Meta.Attrs.KFuzzTest {
		return []uintptr{}, fmt.Errorf("call is not a KFuzzTest call")
	}
	testName, isKFuzzTest := kfuzztest.GetTestName(call.Meta)
	if !isKFuzzTest {
		return []uintptr{}, fmt.Errorf("tried to execute a syscall that wasn't syz_kfuzztest_run")
	}

	dataArg, ok := call.Args[1].(*prog.PointerArg)
	if !ok {
		return []uintptr{}, fmt.Errorf("second arg for syz_kfuzztest_run should be a pointer")
	}
	finalBlob := prog.MarshallKFuzztestArg(dataArg.Res)
	inputPath := kfuzztest.GetInputFilepath(testName)

	res := st.Trace(func() error { return osutil.WriteFile(inputPath, finalBlob) })
	return res.Coverage, res.Result
}
