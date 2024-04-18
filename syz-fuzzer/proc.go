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
	tool     *FuzzerTool
	pid      int
	env      *ipc.Env
	execOpts *ipc.ExecOpts
}

func newProc(tool *FuzzerTool, execOpts *ipc.ExecOpts, pid int) (*Proc, error) {
	env, err := ipc.MakeEnv(tool.config, pid)
	if err != nil {
		return nil, err
	}
	proc := &Proc{
		tool:     tool,
		pid:      pid,
		env:      env,
		execOpts: execOpts,
	}
	return proc, nil
}

func (proc *Proc) loop() {
	rnd := rand.New(rand.NewSource(time.Now().UnixNano() + int64(proc.pid)))
	for {
		req := proc.nextRequest()
		opts := *proc.execOpts
		if req.NeedSignal == rpctype.NoSignal {
			opts.ExecFlags &= ^ipc.FlagCollectSignal
		}
		if req.NeedCover {
			opts.ExecFlags |= ipc.FlagCollectCover
		}
		if req.NeedHints {
			opts.ExecFlags |= ipc.FlagCollectComps
		}
		if req.NeedRawCover {
			opts.ExecFlags &= ^ipc.FlagDedupCover
		}
		// Do not let too much state accumulate.
		const restartIn = 600
		restart := rnd.Intn(restartIn) == 0
		if (restart || proc.tool.resetAccState) &&
			(req.NeedCover || req.NeedSignal != rpctype.NoSignal || req.NeedHints) {
			proc.env.ForceRestart()
		}
		info, try := proc.execute(&opts, req.ID, req.ProgData)
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

func (proc *Proc) execute(opts *ipc.ExecOpts, progID int64, progData []byte) (*ipc.ProgInfo, int) {
	for try := 0; ; try++ {
		var output []byte
		var info *ipc.ProgInfo
		var hanged bool
		// On a heavily loaded VM, syz-executor may take significant time to start.
		// Let's do it outside of the gate ticket.
		err := proc.env.RestartIfNeeded(opts)
		if err == nil {
			// Limit concurrency.
			ticket := proc.tool.gate.Enter()
			proc.tool.startExecutingCall(progID, proc.pid, try)
			output, info, hanged, err = proc.env.ExecProg(opts, progData)
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
