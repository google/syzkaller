// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"fmt"
	"math/rand"
	"os"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/ipc"
	. "github.com/google/syzkaller/pkg/log"
	. "github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/prog"
)

const (
	programLength = 30
)

// Proc represents a single fuzzing process (executor).
type Proc struct {
	fuzzer *Fuzzer
	pid    int
	env    *ipc.Env
	rnd    *rand.Rand
}

func newProc(fuzzer *Fuzzer, pid int) (*Proc, error) {
	env, err := ipc.MakeEnv(fuzzer.config, pid)
	if err != nil {
		return nil, err
	}
	rnd := rand.New(rand.NewSource(time.Now().UnixNano() + int64(pid)*1e12))
	proc := &Proc{
		fuzzer: fuzzer,
		pid:    pid,
		env:    env,
		rnd:    rnd,
	}
	return proc, nil
}

func (proc *Proc) loop() {
	pid := proc.pid
	execOpts := proc.fuzzer.execOpts
	ct := proc.fuzzer.choiceTable

	for i := 0; ; i++ {
		item := proc.fuzzer.workQueue.dequeue()
		if item != nil {
			switch item := item.(type) {
			case *WorkTriage:
				proc.triageInput(item)
			case *WorkCandidate:
				proc.execute(execOpts, item.p, false, item.minimized,
					item.smashed, true, false, StatCandidate)
			case *WorkSmash:
				proc.smashInput(item)
			default:
				panic("unknown work type")
			}
			continue
		}

		corpus := proc.fuzzer.corpusSnapshot()
		if len(corpus) == 0 || i%100 == 0 {
			// Generate a new prog.
			p := proc.fuzzer.target.Generate(proc.rnd, programLength, ct)
			Logf(1, "#%v: generated", pid)
			proc.execute(execOpts, p, false, false, false, false, false, StatGenerate)
		} else {
			// Mutate an existing prog.
			p := corpus[proc.rnd.Intn(len(corpus))].Clone()
			p.Mutate(proc.rnd, programLength, ct, corpus)
			Logf(1, "#%v: mutated", pid)
			proc.execute(execOpts, p, false, false, false, false, false, StatFuzz)
		}
	}
}

func (proc *Proc) triageInput(item *WorkTriage) {
	Logf(1, "#%v: triaging minimized=%v candidate=%v", proc.pid, item.minimized, item.candidate)

	execOpts := proc.fuzzer.execOpts
	if !proc.fuzzer.coverageEnabled {
		panic("should not be called when coverage is disabled")
	}

	newSignal := proc.fuzzer.corpusSignalDiff(item.signal)
	if len(newSignal) == 0 {
		return
	}
	newSignal = cover.Canonicalize(newSignal)

	call := item.p.Calls[item.call].Meta

	Logf(3, "triaging input for %v (new signal=%v)", call.CallName, len(newSignal))
	var inputCover cover.Cover
	opts := *execOpts
	opts.Flags |= ipc.FlagCollectCover
	opts.Flags &= ^ipc.FlagCollide
	const (
		signalRuns       = 3
		minimizeAttempts = 3
	)
	// Compute input coverage and non-flaky signal for minimization.
	notexecuted := 0
	for i := 0; i < signalRuns; i++ {
		info := proc.executeRaw(&opts, item.p, StatTriage)
		if len(info) == 0 || len(info[item.call].Signal) == 0 {
			// The call was not executed. Happens sometimes.
			notexecuted++
			if notexecuted > signalRuns/2 {
				return // if happens too often, give up
			}
			continue
		}
		inf := info[item.call]
		newSignal = cover.Intersection(newSignal, cover.Canonicalize(inf.Signal))
		// Without !minimized check manager starts losing some considerable amount
		// of coverage after each restart. Mechanics of this are not completely clear.
		if len(newSignal) == 0 && !item.minimized {
			return
		}
		if len(inputCover) == 0 {
			inputCover = append([]uint32{}, inf.Cover...)
		} else {
			inputCover = cover.Union(inputCover, inf.Cover)
		}
	}
	if !item.minimized {
		item.p, item.call = prog.Minimize(item.p, item.call, func(p1 *prog.Prog, call1 int) bool {
			for i := 0; i < minimizeAttempts; i++ {
				info := proc.execute(execOpts, p1, false, false, false, false, true, StatMinimize)
				if len(info) == 0 || len(info[call1].Signal) == 0 {
					continue // The call was not executed.
				}
				inf := info[call1]
				signal := cover.Canonicalize(inf.Signal)
				if len(cover.Intersection(newSignal, signal)) == len(newSignal) {
					return true
				}
			}
			return false
		}, false)
	}

	data := item.p.Serialize()
	sig := hash.Hash(data)

	Logf(2, "added new input for %v to corpus:\n%s", call.CallName, data)
	proc.fuzzer.sendInputToManager(RpcInput{
		Call:   call.CallName,
		Prog:   data,
		Signal: []uint32(cover.Canonicalize(item.signal)),
		Cover:  []uint32(inputCover),
	})

	proc.fuzzer.addInputToCorpus(item.p, item.signal, sig)

	if !item.smashed {
		proc.fuzzer.workQueue.enqueue(&WorkSmash{item.p, item.call})
	}
}

func (proc *Proc) smashInput(item *WorkSmash) {
	if proc.fuzzer.faultInjectionEnabled {
		proc.failCall(item.p, item.call)
	}
	if proc.fuzzer.comparisonTracingEnabled {
		proc.executeHintSeed(item.p, item.call)
	}
	corpus := proc.fuzzer.corpusSnapshot()
	for i := 0; i < 100; i++ {
		p := item.p.Clone()
		p.Mutate(proc.rnd, programLength, proc.fuzzer.choiceTable, corpus)
		Logf(1, "#%v: smash mutated", proc.pid)
		proc.execute(proc.fuzzer.execOpts, p, false, false, false, false, false, StatSmash)
	}
}

func (proc *Proc) failCall(p *prog.Prog, call int) {
	for nth := 0; nth < 100; nth++ {
		Logf(1, "#%v: injecting fault into call %v/%v", proc.pid, call, nth)
		opts := *proc.fuzzer.execOpts
		opts.Flags |= ipc.FlagInjectFault
		opts.FaultCall = call
		opts.FaultNth = nth
		info := proc.executeRaw(&opts, p, StatSmash)
		if info != nil && len(info) > call && !info[call].FaultInjected {
			break
		}
	}
}

func (proc *Proc) executeHintSeed(p *prog.Prog, call int) {
	Logf(1, "#%v: collecting comparisons", proc.pid)
	// First execute the original program to dump comparisons from KCOV.
	info := proc.execute(proc.fuzzer.execOpts, p, true, false, false, false, true, StatSeed)
	if info == nil {
		return
	}

	// Then mutate the initial program for every match between
	// a syscall argument and a comparison operand.
	// Execute each of such mutants to check if it gives new coverage.
	p.MutateWithHints(call, info[call].Comps, func(p *prog.Prog) {
		Logf(1, "#%v: executing comparison hint", proc.pid)
		proc.execute(proc.fuzzer.execOpts, p, false, false, false, false, false, StatHint)
	})
}

func (proc *Proc) execute(execOpts *ipc.ExecOpts, p *prog.Prog,
	needComps, minimized, smashed, candidate, noCollide bool, stat Stat) []ipc.CallInfo {
	opts := *execOpts
	if needComps {
		opts.Flags |= ipc.FlagCollectComps
	}
	if noCollide {
		opts.Flags &= ^ipc.FlagCollide
	}

	info := proc.executeRaw(&opts, p, stat)

	for _, callIndex := range proc.fuzzer.checkNewSignal(info) {
		proc.fuzzer.workQueue.enqueue(&WorkTriage{
			p:         p.Clone(),
			call:      callIndex,
			signal:    append([]uint32{}, info[callIndex].Signal...),
			candidate: candidate,
			minimized: minimized,
			smashed:   smashed,
		})
	}
	return info
}

var logMu sync.Mutex

func (proc *Proc) executeRaw(opts *ipc.ExecOpts, p *prog.Prog, stat Stat) []ipc.CallInfo {
	if opts.Flags&ipc.FlagDedupCover == 0 {
		panic("dedup cover is not enabled")
	}

	// Limit concurrency window and do leak checking once in a while.
	ticket := proc.fuzzer.gate.Enter()
	defer proc.fuzzer.gate.Leave(ticket)

	proc.logProgram(opts, p)
	try := 0
retry:
	atomic.AddUint64(&proc.fuzzer.stats[stat], 1)
	output, info, failed, hanged, err := proc.env.Exec(opts, p)
	if failed {
		// BUG in output should be recognized by manager.
		Logf(0, "BUG: executor-detected bug:\n%s", output)
		// Don't return any cover so that the input is not added to corpus.
		return nil
	}
	if err != nil {
		if _, ok := err.(ipc.ExecutorFailure); ok || try > 10 {
			panic(err)
		}
		try++
		Logf(4, "fuzzer detected executor failure='%v', retrying #%d\n", err, (try + 1))
		debug.FreeOSMemory()
		time.Sleep(time.Second)
		goto retry
	}
	Logf(2, "result failed=%v hanged=%v: %v\n", failed, hanged, string(output))
	return info
}

func (proc *Proc) logProgram(opts *ipc.ExecOpts, p *prog.Prog) {
	if proc.fuzzer.outputType == OutputNone {
		return
	}

	data := p.Serialize()
	strOpts := ""
	if opts.Flags&ipc.FlagInjectFault != 0 {
		strOpts = fmt.Sprintf(" (fault-call:%v fault-nth:%v)", opts.FaultCall, opts.FaultNth)
	}

	// The following output helps to understand what program crashed kernel.
	// It must not be intermixed.
	switch proc.fuzzer.outputType {
	case OutputStdout:
		logMu.Lock()
		Logf(0, "executing program %v%v:\n%s", proc.pid, strOpts, data)
		logMu.Unlock()
	case OutputDmesg:
		fd, err := syscall.Open("/dev/kmsg", syscall.O_WRONLY, 0)
		if err == nil {
			buf := new(bytes.Buffer)
			fmt.Fprintf(buf, "syzkaller: executing program %v%v:\n%s",
				proc.pid, strOpts, data)
			syscall.Write(fd, buf.Bytes())
			syscall.Close(fd)
		}
	case OutputFile:
		f, err := os.Create(fmt.Sprintf("%v-%v.prog", proc.fuzzer.name, proc.pid))
		if err == nil {
			if strOpts != "" {
				fmt.Fprintf(f, "#%v\n", strOpts)
			}
			f.Write(data)
			f.Close()
		}
	default:
		panic("unknown output type")
	}
}
