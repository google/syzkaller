// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"fmt"
	"math/rand"
	"os"
	"runtime/debug"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mab"
	"github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/prog"
)

// Proc represents a single fuzzing process (executor).
type Proc struct {
	fuzzer            *Fuzzer
	pid               int
	env               *ipc.Env
	rnd               *rand.Rand
	execOpts          *ipc.ExecOpts
	execOptsCover     *ipc.ExecOpts
	execOptsComps     *ipc.ExecOpts
	execOptsNoCollide *ipc.ExecOpts
}

func newProc(fuzzer *Fuzzer, pid int) (*Proc, error) {
	env, err := ipc.MakeEnv(fuzzer.config, pid)
	if err != nil {
		return nil, err
	}
	rnd := rand.New(rand.NewSource(time.Now().UnixNano() + int64(pid)*1e12))
	execOptsNoCollide := *fuzzer.execOpts
	execOptsNoCollide.Flags &= ^ipc.FlagCollide
	execOptsCover := execOptsNoCollide
	execOptsCover.Flags |= ipc.FlagCollectCover
	execOptsComps := execOptsNoCollide
	execOptsComps.Flags |= ipc.FlagCollectComps
	proc := &Proc{
		fuzzer:            fuzzer,
		pid:               pid,
		env:               env,
		rnd:               rnd,
		execOpts:          fuzzer.execOpts,
		execOptsCover:     &execOptsCover,
		execOptsComps:     &execOptsComps,
		execOptsNoCollide: &execOptsNoCollide,
	}
	return proc, nil
}

func (proc *Proc) ProcessItem(item interface{}) *mab.TriageResult {
	if item != nil {
		switch item := item.(type) {
		case *WorkTriage:
			{
				res := proc.triageInput(item)
				return &res
			}
		case *WorkCandidate:
			{
				proc.execute(proc.execOpts, item.p, item.flags, StatCandidate)
				return nil
			}
		case *WorkSmash:
			{
				proc.smashInput(item)
				return nil
			}
		default:
			log.Fatalf("unknown work type: %#v", item)
		}
	}
	return nil
}

func (proc *Proc) loop() {
	generatePeriod := 100
	if proc.fuzzer.config.Flags&ipc.FlagSignal == 0 {
		// If we don't have real coverage signal, generate programs more frequently
		// because fallback signal is weak.
		generatePeriod = 2
	}
	for i := 0; ; i++ {
		// Could have race condition. However, this parameter
		// is not that important
		proc.fuzzer.MABStatus.Round++

		// If we use MAB for task selection
		if proc.fuzzer.MABStatus.TSEnabled {
			proc.clearQueue()
			proc.MABLoop()
			continue
		}

		item := proc.fuzzer.workQueue.dequeue(DequeueOptionAny)
		if item != nil {
			r := proc.ProcessItem(item)
			if r != nil {
				log.Logf(0, "Work Type: 2, Result: %+v\n", r)
			}
			continue
		}

		ct := proc.fuzzer.choiceTable
		fuzzerSnapshot := proc.fuzzer.snapshot()
		if len(fuzzerSnapshot.corpus) == 0 || i%generatePeriod == 0 {
			// Generate a new prog.
			ts0 := time.Now().UnixNano()
			p := proc.fuzzer.target.Generate(proc.rnd, prog.RecommendedCalls, ct)
			log.Logf(1, "#%v: generated", proc.pid)
			_, r := proc.execute(proc.execOpts, p, ProgNormal, StatGenerate)
			r.TimeTotal = float64(time.Now().UnixNano()-ts0) / MABTimeUnit
			log.Logf(0, "Work Type: 0, Result: %+v\n", r)
		} else {
			// Mutate an existing prog.
			ts0 := time.Now().UnixNano()
			pidx, p := fuzzerSnapshot.chooseProgram(proc.rnd)
			p = p.Clone()
			p.ResetReward()
			p.Mutate(proc.rnd, prog.RecommendedCalls, ct, fuzzerSnapshot.corpus)
			log.Logf(1, "#%v: mutated", proc.pid)
			_, r := proc.execute(proc.execOpts, p, ProgNormal, StatFuzz)
			r.Pidx = pidx
			r.TimeTotal = float64(time.Now().UnixNano()-ts0) / MABTimeUnit
			if proc.fuzzer.MABStatus.SSEnabled {
				proc.fuzzer.MABStatus.UpdateWeight(1, r, []float64{1.0, 1.0, 1.0})
			}
			log.Logf(0, "Work Type: 1, Result: %+v\n", r)
		}
	}
}

func (proc *Proc) triageInput(item *WorkTriage) mab.TriageResult {
	log.Logf(1, "#%v: triaging type=%x", proc.pid, item.flags)
	tsBgn := time.Now().UnixNano()
	sourceData := item.p.Serialize()
	sourceSig := hash.Hash(sourceData)
	ret := mab.TriageResult{
		CorpusCov:        0,
		SourceExecTime:   0.0,
		MinimizeCov:      0,
		VerifyTime:       0.0,
		MinimizeTime:     0.0,
		Source:           item.p.Source,
		SourceSig:        sourceSig,
		MinimizeTimeSave: 0.0,
		Pidx:             -1,
		Success:          false,
		TimeTotal:        0.0,
	}

	prio := signalPrio(item.p, &item.info, item.call)
	inputSignal := signal.FromRaw(item.info.Signal, prio)
	newSignal := proc.fuzzer.corpusSignalDiff(inputSignal)
	if newSignal.Empty() {
		return ret
	}
	callName := ".extra"
	logCallName := "extra"
	if item.call != -1 {
		callName = item.p.Calls[item.call].Meta.Name
		logCallName = fmt.Sprintf("call #%v %v", item.call, callName)
	}
	log.Logf(3, "triaging input for %v (new signal=%v)", logCallName, newSignal.Len())
	var inputCover cover.Cover
	const (
		signalRuns       = 3
		minimizeAttempts = 3
	)
	// Compute input coverage and non-flaky signal for minimization.
	notexecuted := 0
	for i := 0; i < signalRuns; i++ {
		info, timeExec := proc.executeRaw(proc.execOptsCover, item.p, StatTriage)
		ret.VerifyTime += timeExec
		if !reexecutionSuccess(info, &item.info, item.call) {
			// The call was not executed or failed.
			notexecuted++
			if notexecuted > signalRuns/2+1 {
				ret.TimeTotal = float64(time.Now().UnixNano()-tsBgn) / MABTimeUnit
				ret.CorpusCov = 0.0
				return ret // if happens too often, give up
			}
			continue
		}
		thisSignal, thisCover := getSignalAndCover(item.p, info, item.call)
		newSignal = newSignal.Intersection(thisSignal)
		// Without !minimized check manager starts losing some considerable amount
		// of coverage after each restart. Mechanics of this are not completely clear.
		if newSignal.Empty() && item.flags&ProgMinimized == 0 {
			ret.TimeTotal = float64(time.Now().UnixNano()-tsBgn) / MABTimeUnit
			return ret
		}
		inputCover.Merge(thisCover)
	}
	minimizeTimeBefore := ret.VerifyTime / float64(signalRuns)
	ret.SourceExecTime = minimizeTimeBefore
	minimizeTimeAfter := minimizeTimeBefore
	if item.flags&ProgMinimized == 0 {
		item.p, item.call = prog.Minimize(item.p, item.call, false,
			func(p1 *prog.Prog, call1 int) bool {
				p1.Source = 2
				timeAverage := 0.0

				for i := 0; i < minimizeAttempts; i++ {
					var info *ipc.ProgInfo
					var r mab.ExecResult
					info, r = proc.execute(proc.execOptsNoCollide, p1, ProgNormal, StatMinimize)
					ret.MinimizeCov += r.Cov
					ret.MinimizeTime += r.TimeExec
					timeAverage += r.TimeExec

					if !reexecutionSuccess(info, &item.info, call1) {
						// The call was not executed or failed.
						continue
					}
					thisSignal, _ := getSignalAndCover(p1, info, call1)
					if newSignal.Intersection(thisSignal).Len() == newSignal.Len() {
						timeAverage = timeAverage / float64(i+1)
						minimizeTimeAfter = timeAverage
						return true
					}
				}
				return false
			})
	}
	ret.MinimizeTimeSave = minimizeTimeBefore - minimizeTimeAfter

	data := item.p.Serialize()
	sig := hash.Hash(data)

	item.p.CorpusReward = mab.CorpusReward{
		VerifyTime:       ret.VerifyTime,
		MinimizeCov:      float64(ret.MinimizeCov),
		MinimizeTime:     ret.MinimizeTime,
		MinimizeTimeSave: ret.MinimizeTimeSave,
	}

	log.Logf(2, "added new input for %v to corpus:\n%s", logCallName, data)
	proc.fuzzer.sendInputToManager(rpctype.RPCInput{
		Call:   callName,
		Prog:   data,
		Signal: inputSignal.Serialize(),
		Cover:  inputCover.Serialize(),
		Reward: item.p.CorpusReward,
	})

	ret.Pidx = proc.fuzzer.addInputToCorpus(item.p, inputSignal, sig)
	ret.CorpusCov = len(inputSignal)

	if item.flags&ProgSmashed == 0 {
		proc.fuzzer.workQueue.enqueue(&WorkSmash{item.p, item.call})
	}

	tsEnd := time.Now().UnixNano()
	ret.TimeTotal = float64(tsEnd-tsBgn) / MABTimeUnit
	ret.Success = true
	return ret
}

func reexecutionSuccess(info *ipc.ProgInfo, oldInfo *ipc.CallInfo, call int) bool {
	if info == nil || len(info.Calls) == 0 {
		return false
	}
	if call != -1 {
		// Don't minimize calls from successful to unsuccessful.
		// Successful calls are much more valuable.
		if oldInfo.Errno == 0 && info.Calls[call].Errno != 0 {
			return false
		}
		return len(info.Calls[call].Signal) != 0
	}
	return len(info.Extra.Signal) != 0
}

func getSignalAndCover(p *prog.Prog, info *ipc.ProgInfo, call int) (signal.Signal, []uint32) {
	inf := &info.Extra
	if call != -1 {
		inf = &info.Calls[call]
	}
	return signal.FromRaw(inf.Signal, signalPrio(p, inf, call)), inf.Cover
}

func (proc *Proc) smashInput(item *WorkSmash) {
	// If MABSS enabled, only do this for first-timers
	if proc.fuzzer.faultInjectionEnabled && item.call != -1 {
		proc.failCall(item.p, item.call)
	}
	if proc.fuzzer.comparisonTracingEnabled && item.call != -1 {
		proc.executeHintSeed(item.p, item.call)
	}
	// If MABSS or MABTS enabled, do not mutate at all
	if proc.fuzzer.MABStatus.SSEnabled || proc.fuzzer.MABStatus.TSEnabled {
		return
	}
	fuzzerSnapshot := proc.fuzzer.snapshot()
	smashCount := 100
	for i := 0; i < smashCount; i++ {
		p := item.p.Clone()
		p.Mutate(proc.rnd, prog.RecommendedCalls, proc.fuzzer.choiceTable, fuzzerSnapshot.corpus)
		log.Logf(1, "#%v: smash mutated", proc.pid)
		proc.execute(proc.execOpts, p, ProgNormal, StatSmash)
	}
}

func (proc *Proc) failCall(p *prog.Prog, call int) {
	for nth := 0; nth < 100; nth++ {
		log.Logf(1, "#%v: injecting fault into call %v/%v", proc.pid, call, nth)
		opts := *proc.execOpts
		opts.Flags |= ipc.FlagInjectFault
		opts.FaultCall = call
		opts.FaultNth = nth
		info, _ := proc.executeRaw(&opts, p, StatSmash)
		if info != nil && len(info.Calls) > call && info.Calls[call].Flags&ipc.CallFaultInjected == 0 {
			break
		}
	}
}

func (proc *Proc) executeHintSeed(p *prog.Prog, call int) {
	log.Logf(1, "#%v: collecting comparisons", proc.pid)
	// First execute the original program to dump comparisons from KCOV.
	info, _ := proc.execute(proc.execOptsComps, p, ProgNormal, StatSeed)
	if info == nil {
		return
	}

	// Then mutate the initial program for every match between
	// a syscall argument and a comparison operand.
	// Execute each of such mutants to check if it gives new coverage.
	p.MutateWithHints(call, info.Calls[call].Comps, func(p *prog.Prog) {
		log.Logf(1, "#%v: executing comparison hint", proc.pid)
		proc.execute(proc.execOpts, p, ProgNormal, StatHint)
	})
}

func (proc *Proc) execute(execOpts *ipc.ExecOpts, p *prog.Prog, flags ProgTypes,
	stat Stat) (*ipc.ProgInfo, mab.ExecResult) {
	ret := mab.ExecResult{
		Cov:       0,
		TimeExec:  0.0,
		TimeTotal: 0.0,
		Pidx:      -1,
	}
	info, time := proc.executeRaw(execOpts, p, stat)
	ret.TimeExec = time
	p.CorpusReward.ExecTime = time
	calls, extra, cov := proc.fuzzer.checkNewSignal(p, info)
	ret.Cov = cov
	for _, callIndex := range calls {
		proc.enqueueCallTriage(p, flags, callIndex, info.Calls[callIndex])
	}
	if extra {
		proc.enqueueCallTriage(p, flags, -1, info.Extra)
	}
	return info, ret
}

func (proc *Proc) enqueueCallTriage(p *prog.Prog, flags ProgTypes, callIndex int, info ipc.CallInfo) {
	// info.Signal points to the output shmem region, detach it before queueing.
	info.Signal = append([]uint32{}, info.Signal...)
	// None of the caller use Cover, so just nil it instead of detaching.
	// Note: triage input uses executeRaw to get coverage.
	info.Cover = nil
	proc.fuzzer.workQueue.enqueue(&WorkTriage{
		p:     p.Clone(),
		call:  callIndex,
		info:  info,
		flags: flags,
	})
}

func (proc *Proc) executeRaw(opts *ipc.ExecOpts, p *prog.Prog, stat Stat) (*ipc.ProgInfo, float64) {
	if opts.Flags&ipc.FlagDedupCover == 0 {
		log.Fatalf("dedup cover is not enabled")
	}
	for _, call := range p.Calls {
		if !proc.fuzzer.choiceTable.Enabled(call.Meta.ID) {
			panic(fmt.Sprintf("executing disabled syscall %v", call.Meta.Name))
		}
	}

	// Limit concurrency window and do leak checking once in a while.
	ticket := proc.fuzzer.gate.Enter()
	defer proc.fuzzer.gate.Leave(ticket)

	proc.logProgram(opts, p)
	ts := time.Now().UnixNano()
	for try := 0; ; try++ {
		atomic.AddUint64(&proc.fuzzer.stats[stat], 1)
		output, info, hanged, err := proc.env.Exec(opts, p)
		if err != nil {
			if try > 10 {
				log.Fatalf("executor %v failed %v times:\n%v", proc.pid, try, err)
			}
			log.Logf(4, "fuzzer detected executor failure='%v', retrying #%d", err, try+1)
			debug.FreeOSMemory()
			time.Sleep(time.Second)
			continue
		}
		log.Logf(2, "result hanged=%v: %s", hanged, output)
		tsEnd := time.Now().UnixNano()
		return info, float64(tsEnd-ts) / MABTimeUnit
	}
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
		now := time.Now()
		proc.fuzzer.logMu.Lock()
		fmt.Printf("%02v:%02v:%02v executing program %v%v:\n%s\n",
			now.Hour(), now.Minute(), now.Second(),
			proc.pid, strOpts, data)
		proc.fuzzer.logMu.Unlock()
	case OutputDmesg:
		fd, err := syscall.Open("/dev/kmsg", syscall.O_WRONLY, 0)
		if err == nil {
			buf := new(bytes.Buffer)
			fmt.Fprintf(buf, "syzkaller: executing program %v%v:\n%s\n",
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
		log.Fatalf("unknown output type: %v", proc.fuzzer.outputType)
	}
}
