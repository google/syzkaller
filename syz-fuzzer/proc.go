// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"fmt"
	"math/rand"
	"os"
	"runtime/debug"
	"syscall"
	"time"

	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/prog"
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
			opts.Flags &= ^ipc.FlagCollectSignal
		}
		if req.NeedCover {
			opts.Flags |= ipc.FlagCollectCover
		}
		if req.NeedHints {
			opts.Flags |= ipc.FlagCollectComps
		}
		if req.NeedRawCover {
			opts.Flags &= ^ipc.FlagDedupCover
		}
		// Do not let too much state accumulate.
		const restartIn = 600
		restart := rnd.Intn(restartIn) == 0
		if (restart || proc.tool.resetAccState) &&
			(req.NeedCover || req.NeedSignal != rpctype.NoSignal || req.NeedHints) {
			proc.env.ForceRestart()
		}
		info := proc.executeRaw(&opts, req.prog)
		// Let's perform signal filtering in a separate thread to get the most
		// exec/sec out of a syz-executor instance.
		proc.tool.results <- executionResult{
			ExecutionRequest: req.ExecutionRequest,
			info:             info,
		}
	}
}

func (proc *Proc) nextRequest() executionRequest {
	select {
	case req := <-proc.tool.inputs:
		return req
	default:
	}
	// Not having enough inputs to execute is a sign of RPC communication problems.
	// Let's count and report such situations.
	proc.tool.noExecRequests.Add(1)
	return <-proc.tool.inputs
}

func (proc *Proc) executeRaw(opts *ipc.ExecOpts, p *prog.Prog) *ipc.ProgInfo {
	for try := 0; ; try++ {
		var output []byte
		var info *ipc.ProgInfo
		var hanged bool
		// On a heavily loaded VM, syz-executor may take significant time to start.
		// Let's do it outside of the gate ticket.
		err := proc.env.RestartIfNeeded(p.Target)
		if err == nil {
			// Limit concurrency.
			ticket := proc.tool.gate.Enter()
			proc.logProgram(opts, p)
			output, info, hanged, err = proc.env.Exec(opts, p)
			proc.tool.gate.Leave(ticket)
		}
		if err != nil {
			if err == prog.ErrExecBufferTooSmall {
				// It's bad if we systematically fail to serialize programs,
				// but so far we don't have a better handling than counting this.
				// This error is observed a lot on the seeded syz_mount_image calls.
				proc.tool.bufferTooSmall.Add(1)
				return nil
			}
			if try > 10 {
				log.SyzFatalf("executor %v failed %v times: %v", proc.pid, try, err)
			}
			log.Logf(4, "fuzzer detected executor failure='%v', retrying #%d", err, try+1)
			debug.FreeOSMemory()
			time.Sleep(time.Second)
			continue
		}
		log.Logf(2, "result hanged=%v: %s", hanged, output)
		return info
	}
}

func (proc *Proc) logProgram(opts *ipc.ExecOpts, p *prog.Prog) {
	if proc.tool.outputType == OutputNone {
		return
	}

	data := p.Serialize()

	// The following output helps to understand what program crashed kernel.
	// It must not be intermixed.
	switch proc.tool.outputType {
	case OutputStdout:
		now := time.Now()
		proc.tool.logMu.Lock()
		fmt.Printf("%02v:%02v:%02v executing program %v:\n%s\n",
			now.Hour(), now.Minute(), now.Second(),
			proc.pid, data)
		proc.tool.logMu.Unlock()
	case OutputDmesg:
		fd, err := syscall.Open("/dev/kmsg", syscall.O_WRONLY, 0)
		if err == nil {
			buf := new(bytes.Buffer)
			fmt.Fprintf(buf, "syzkaller: executing program %v:\n%s\n",
				proc.pid, data)
			syscall.Write(fd, buf.Bytes())
			syscall.Close(fd)
		}
	case OutputFile:
		f, err := os.Create(fmt.Sprintf("%v-%v.prog", proc.tool.name, proc.pid))
		if err == nil {
			f.Write(data)
			f.Close()
		}
	default:
		log.SyzFatalf("unknown output type: %v", proc.tool.outputType)
	}
}
