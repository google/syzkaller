package kfuzztest

import (
	"context"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/kcov"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/prog"
)

type ExecResult struct {
	Call    *prog.Call
	Success bool
}

// KFuzzTestExecutor is an executor that when receives requests, will execute a
// a KFuzzTest target.
type KFuzzTestExecutor struct {
	ctx      context.Context
	jobChan  chan *queue.Request
	statChan chan ExecResult
	// Timeout between processing requests.
	timeout time.Duration
	wg      sync.WaitGroup
}

// Implements the queue.Executor interface.
func (kfe *KFuzzTestExecutor) Submit(req *queue.Request) {
	kfe.jobChan <- req
}

func (kfe *KFuzzTestExecutor) Shutdown() {
	close(kfe.jobChan)
	kfe.wg.Wait()
}

func NewKFuzzTestExecutor(ctx context.Context, numWorkers int, statChan chan ExecResult) *KFuzzTestExecutor {
	jobChan := make(chan *queue.Request)

	kfe := &KFuzzTestExecutor{
		ctx:      ctx,
		jobChan:  jobChan,
		statChan: statChan,
		timeout:  0, // 500 * time.Millisecond,
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

			res := ExecResult{Call: call, Success: true}

			// Trace each individual call, collecting the covered PCs.
			coverage, err := kcovSt.Trace(func() error { return ExecKFuzzTestCallLocal(call) })
			if err != nil {
				// Set this call info as a failure. -1 is a placeholder.
				callInfo.Error = -1
				callInfo.Flags |= flatrpc.CallFlagBlocked
				res.Success = false
			} else {
				for _, pc := range coverage {
					callInfo.Signal = append(callInfo.Signal, uint64(pc))
				}
				callInfo.Flags |= flatrpc.CallFlagExecuted
			}

			info.Calls = append(info.Calls, callInfo)
			kfe.statChan <- res
		}

		req.Done(&queue.Result{Info: info, Executor: queue.ExecutorID{VM: 0, Proc: tid}})

		if kfe.timeout != 0 {
			time.Sleep(kfe.timeout)
		}
	}
	log.Logf(0, "thread_%d exiting", tid)
}
