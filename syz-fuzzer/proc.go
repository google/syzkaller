// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/signal"
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
	for {
		req, wait := proc.nextRequest()
		if req.Flags&flatrpc.RequestFlagResetState != 0 {
			proc.env.ForceRestart()
		}
		info, output, err := proc.execute(req, wait)
		res := &flatrpc.ExecResult{
			Id:     req.Id,
			Info:   info,
			Output: output,
			Error:  err,
		}
		for i := 1; i < int(req.Repeat) && res.Error == "" && req.Flags&flatrpc.RequestFlagIsBinary == 0; i++ {
			// Recreate Env every few iterations, this allows to cover more paths.
			if i%2 == 0 {
				proc.env.ForceRestart()
			}
			info, output, err := proc.execute(req, 0)
			if res.Info == nil {
				res.Info = info
			} else if info != nil {
				res.Info.Calls = append(res.Info.Calls, info.Calls...)
			}
			res.Output = append(res.Output, output...)
			res.Error = err
		}
		if res.Info != nil {
			filter := signal.FromRaw(req.SignalFilter, 0)
			proc.tool.diffMaxSignal(res.Info, filter, int(req.SignalFilterCall), req.AllSignal)
		}
		msg := &flatrpc.ExecutorMessage{
			Msg: &flatrpc.ExecutorMessages{
				Type:  flatrpc.ExecutorMessagesRawExecResult,
				Value: res,
			},
		}
		if err := flatrpc.Send(proc.tool.conn, msg); err != nil {
			log.SyzFatal(err)
		}
	}
}

func (proc *Proc) nextRequest() (*flatrpc.ExecRequest, time.Duration) {
	select {
	case req := <-proc.tool.requests:
		return req, 0
	default:
	}
	// Not having enough inputs to execute is a sign of RPC communication problems.
	// Let's count and report such situations.
	start := osutil.MonotonicNano()
	req := <-proc.tool.requests
	wait := osutil.MonotonicNano() - start
	return req, wait
}

func (proc *Proc) execute(req *flatrpc.ExecRequest, wait time.Duration) (
	info *flatrpc.ProgInfo, output []byte, errStr string) {
	var err error
	if req.Flags&flatrpc.RequestFlagIsBinary != 0 {
		output, err = executeBinary(req)
	} else {
		info, output, err = proc.executeProgram(req, wait)
	}
	if req.Flags&flatrpc.RequestFlagReturnOutput == 0 {
		output = nil
	}
	if err != nil {
		errStr = err.Error()
	}
	return
}

func (proc *Proc) executeProgram(req *flatrpc.ExecRequest, wait time.Duration) (*flatrpc.ProgInfo, []byte, error) {
	returnError := req.Flags&flatrpc.RequestFlagReturnError != 0
	for try := 0; ; try++ {
		var output []byte
		var info *flatrpc.ProgInfo
		var hanged bool
		err := proc.env.RestartIfNeeded(req.ExecOpts)
		if err == nil {
			proc.tool.startExecutingCall(req.Id, proc.pid, try, wait)
			output, info, hanged, err = proc.env.ExecProg(req.ExecOpts, req.ProgData)
			// Don't print output if returning error b/c it may contain SYZFAIL.
			if !returnError {
				log.Logf(2, "result hanged=%v err=%v: %s", hanged, err, output)
			}
			if hanged && err == nil && returnError {
				err = errors.New("hanged")
			}
		}
		if err == nil || returnError {
			return info, output, err
		}
		log.Logf(4, "fuzzer detected executor failure='%v', retrying #%d", err, try+1)
		if try > 10 {
			log.SyzFatalf("executor %v failed %v times: %v\n%s", proc.pid, try, err, output)
		} else if try > 3 {
			time.Sleep(100 * time.Millisecond)
		}
	}
}

func executeBinary(req *flatrpc.ExecRequest) ([]byte, error) {
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
