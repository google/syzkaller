// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"errors"
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"time"

	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/rpctype"
)

// Proc represents a single fuzzing process (executor).
type Proc struct {
	tool *FuzzerTool
	pid  int
	env  *ipc.Env
}

func startProc(tool *FuzzerTool, pid int, config *ipc.Config) {
	env, err := ipc.MakeEnv(config, pid)
	if err != nil {
		log.SyzFatalf("failed to create env: %v", err)
	}
	proc := &Proc{
		tool: tool,
		pid:  pid,
		env:  env,
	}
	go proc.loop()
}

func (proc *Proc) loop() {
	rnd := rand.New(rand.NewSource(time.Now().UnixNano() + int64(proc.pid)))
	for {
		req := proc.nextRequest()
		// Do not let too much state accumulate.
		const restartIn = 600
		if (req.ExecOpts.ExecFlags&(ipc.FlagCollectSignal|ipc.FlagCollectCover|ipc.FlagCollectComps) != 0 &&
			rnd.Intn(restartIn) == 0) || req.ResetState {
			proc.env.ForceRestart()
		}
		info, output, err, try := proc.execute(req)
		res := executionResult{
			ExecutionRequest: req,
			procID:           proc.pid,
			try:              try,
			info:             info,
			output:           output,
			err:              err,
		}
		for i := 1; i < req.Repeat && res.err == "" && !req.IsBinary; i++ {
			// Recreate Env every few iterations, this allows to cover more paths.
			if i%2 == 0 {
				proc.env.ForceRestart()
			}
			info, output, err, _ := proc.execute(req)
			if res.info == nil {
				res.info = info
			} else {
				res.info.Calls = append(res.info.Calls, info.Calls...)
			}
			res.output = append(res.output, output...)
			res.err = err
		}
		// Let's perform signal filtering in a separate thread to get the most
		// exec/sec out of a syz-executor instance.
		proc.tool.results <- res
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

func (proc *Proc) execute(req rpctype.ExecutionRequest) (info *ipc.ProgInfo, output []byte, errStr string, try int) {
	var err error
	if req.IsBinary {
		output, err = executeBinary(req)
	} else {
		info, output, try, err = proc.executeProgram(req)
	}
	if !req.ReturnOutput {
		output = nil
	}
	if err != nil {
		errStr = err.Error()
	}
	return
}

func (proc *Proc) executeProgram(req rpctype.ExecutionRequest) (*ipc.ProgInfo, []byte, int, error) {
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
			// Don't print output if returning error b/c it may contain SYZFAIL.
			if !req.ReturnError {
				log.Logf(2, "result hanged=%v err=%v: %s", hanged, err, output)
			}
			if hanged && err == nil && req.ReturnError {
				err = errors.New("hanged")
			}
		}
		if err == nil || req.ReturnError {
			return info, output, try, err
		}
		log.Logf(4, "fuzzer detected executor failure='%v', retrying #%d", err, try+1)
		if try > 10 {
			log.SyzFatalf("executor %v failed %v times: %v\n%s", proc.pid, try, err, output)
		} else if try > 3 {
			time.Sleep(100 * time.Millisecond)
		}
	}
}

func executeBinary(req rpctype.ExecutionRequest) ([]byte, error) {
	tmp, err := os.MkdirTemp("", "syz-runtest")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(tmp)
	bin := filepath.Join(tmp, "syz-executor")
	if err := os.WriteFile(bin, req.ProgData, 0777); err != nil {
		return nil, fmt.Errorf("failed to write binary: %w", err)
	}
	cmd := osutil.Command(bin)
	cmd.Dir = tmp
	// Tell ASAN to not mess with our NONFAILING.
	cmd.Env = append(append([]string{}, os.Environ()...), "ASAN_OPTIONS=handle_segv=0 allow_user_segv_handler=1")
	output, err := osutil.Run(20*time.Second, cmd)
	var verr *osutil.VerboseError
	if errors.As(err, &verr) {
		// The process can legitimately do something like exit_group(1).
		// So we ignore the error and rely on the rest of the checks (e.g. syscall return values).
		return verr.Output, nil
	}
	return output, err
}
