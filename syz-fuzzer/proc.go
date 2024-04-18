// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"math/rand"
	"time"

	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/rpctype"
)

// Proc represents a single fuzzing process (executor).
type Proc struct {
	tool       *FuzzerTool
	pid        int
	env        *ipc.Env
	resetState bool
}

func startProc(tool *FuzzerTool, pid int, config *ipc.Config, resetState bool) {
	env, err := ipc.MakeEnv(config, pid)
	if err != nil {
		log.SyzFatalf("failed to create env: %v", err)
	}
	proc := &Proc{
		tool:       tool,
		pid:        pid,
		env:        env,
		resetState: resetState,
	}
	go proc.loop()
}

func (proc *Proc) loop() {
	rnd := rand.New(rand.NewSource(time.Now().UnixNano() + int64(proc.pid)))
	for {
		req := proc.nextRequest()
		// Do not let too much state accumulate.
		const restartIn = 600
		if req.ExecOpts.ExecFlags&(ipc.FlagCollectSignal|ipc.FlagCollectCover|ipc.FlagCollectComps) != 0 &&
			(proc.resetState || rnd.Intn(restartIn) == 0) {
			proc.env.ForceRestart()
		}
		info, try := proc.execute(req)
		// Let's perform signal filtering in a separate thread to get the most
		// exec/sec out of a syz-executor instance.
		proc.tool.results <- executionResult{
			ExecutionRequest: req,
			procID:           proc.pid,
			try:              try,
			info:             info,
		}
	}
}

func (proc *Proc) nextRequest() rpctype.ExecutionRequest {
	select {
	case req := <-proc.tool.requests:
		return req
	default:
	}
	// Not having enough inputs to execute is a sign of RPC communication problems.
	// Let's count and report such situations.
	start := osutil.MonotonicNano()
	req := <-proc.tool.requests
	proc.tool.noExecDuration.Add(uint64(osutil.MonotonicNano() - start))
	proc.tool.noExecRequests.Add(1)
	return req
}

func (proc *Proc) execute(req rpctype.ExecutionRequest) (*ipc.ProgInfo, int) {
	for try := 0; ; try++ {
		var output []byte
		var info *ipc.ProgInfo
		var hanged bool
		// On a heavily loaded VM, syz-executor may take significant time to start.
		// Let's do it outside of the gate ticket.
		err := proc.env.RestartIfNeeded(&req.ExecOpts)
		if err == nil {
			// Limit concurrency.
			ticket := proc.tool.gate.Enter()
			proc.tool.startExecutingCall(req.ID, proc.pid, try)
			output, info, hanged, err = proc.env.ExecProg(&req.ExecOpts, req.ProgData)
			proc.tool.gate.Leave(ticket)
			if err == nil {
				log.Logf(2, "result hanged=%v: %s", hanged, output)
				return info, try
			}
		}
		log.Logf(4, "fuzzer detected executor failure='%v', retrying #%d", err, try+1)
		if try > 10 {
			log.SyzFatalf("executor %v failed %v times: %v\n%s", proc.pid, try, err, output)
		} else if try > 3 {
			time.Sleep(100 * time.Millisecond)
		}
	}
}
