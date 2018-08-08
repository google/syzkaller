// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// execprog executes a single program or a set of programs
// and optionally prints information about execution.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/host"
	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/ipc/ipcconfig"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

var (
	flagOS        = flag.String("os", runtime.GOOS, "target os")
	flagArch      = flag.String("arch", runtime.GOARCH, "target arch")
	flagCoverFile = flag.String("coverfile", "", "write coverage to the file")
	flagRepeat    = flag.Int("repeat", 1, "repeat execution that many times (0 for infinite loop)")
	flagProcs     = flag.Int("procs", 1, "number of parallel processes to execute programs")
	flagOutput    = flag.Bool("output", false, "write programs and results to stdout")
	flagFaultCall = flag.Int("fault_call", -1, "inject fault into this call (0-based)")
	flagFaultNth  = flag.Int("fault_nth", 0, "inject fault on n-th operation (0-based)")
	flagHints     = flag.Bool("hints", false, "do a hints-generation run")
)

func main() {
	flag.Parse()
	if len(flag.Args()) == 0 {
		fmt.Fprintf(os.Stderr, "usage: execprog [flags] file-with-programs+\n")
		flag.PrintDefaults()
		os.Exit(1)
	}

	target, err := prog.GetTarget(*flagOS, *flagArch)
	if err != nil {
		log.Fatalf("%v", err)
	}

	entries := loadPrograms(target, flag.Args())
	if len(entries) == 0 {
		return
	}

	features, err := host.Check(target)
	if err != nil {
		log.Fatalf("%v", err)
	}
	if _, err = host.Setup(target, features); err != nil {
		log.Fatalf("%v", err)
	}
	config, execOpts := createConfig(target, entries, features)

	ctx := &Context{
		entries:  entries,
		config:   config,
		execOpts: execOpts,
		gate:     ipc.NewGate(2**flagProcs, nil),
		shutdown: make(chan struct{}),
		repeat:   *flagRepeat,
	}
	var wg sync.WaitGroup
	wg.Add(*flagProcs)
	for p := 0; p < *flagProcs; p++ {
		pid := p
		go func() {
			defer wg.Done()
			ctx.run(pid)
		}()
	}
	osutil.HandleInterrupts(ctx.shutdown)
	wg.Wait()
}

type Context struct {
	entries   []*prog.LogEntry
	config    *ipc.Config
	execOpts  *ipc.ExecOpts
	gate      *ipc.Gate
	shutdown  chan struct{}
	logMu     sync.Mutex
	posMu     sync.Mutex
	repeat    int
	pos       int
	lastPrint time.Time
}

func (ctx *Context) run(pid int) {
	env, err := ipc.MakeEnv(ctx.config, pid)
	if err != nil {
		log.Fatalf("failed to create ipc env: %v", err)
	}
	defer env.Close()
	for {
		select {
		case <-ctx.shutdown:
			return
		default:
		}
		idx := ctx.getProgramIndex()
		if ctx.repeat > 0 && idx >= len(ctx.entries)*ctx.repeat {
			return
		}
		entry := ctx.entries[idx%len(ctx.entries)]
		ctx.execute(pid, env, entry)
	}
}

func (ctx *Context) execute(pid int, env *ipc.Env, entry *prog.LogEntry) {
	// Limit concurrency window.
	ticket := ctx.gate.Enter()
	defer ctx.gate.Leave(ticket)

	callOpts := ctx.execOpts
	if *flagFaultCall == -1 && entry.Fault {
		newOpts := *ctx.execOpts
		newOpts.Flags |= ipc.FlagInjectFault
		newOpts.FaultCall = entry.FaultCall
		newOpts.FaultNth = entry.FaultNth
		callOpts = &newOpts
	}
	if *flagOutput {
		ctx.logProgram(pid, entry.P, callOpts)
	}
	output, info, failed, hanged, err := env.Exec(callOpts, entry.P)
	if failed {
		log.Logf(0, "BUG: executor-detected bug:\n%s", output)
	}
	if ctx.config.Flags&ipc.FlagDebug != 0 || err != nil {
		log.Logf(0, "result: failed=%v hanged=%v err=%v\n\n%s",
			failed, hanged, err, output)
	}
	if len(info) != 0 {
		ctx.printCallResults(info)
		if *flagHints {
			ctx.printHints(entry.P, info)
		}
	} else {
		log.Logf(1, "RESULT: no calls executed")
	}
	if *flagCoverFile != "" {
		ctx.dumpCoverage(*flagCoverFile, info)
	}
}

func (ctx *Context) logProgram(pid int, p *prog.Prog, callOpts *ipc.ExecOpts) {
	strOpts := ""
	if callOpts.Flags&ipc.FlagInjectFault != 0 {
		strOpts = fmt.Sprintf(" (fault-call:%v fault-nth:%v)",
			callOpts.FaultCall, callOpts.FaultNth)
	}
	data := p.Serialize()
	ctx.logMu.Lock()
	log.Logf(0, "executing program %v%v:\n%s", pid, strOpts, data)
	ctx.logMu.Unlock()
}

func (ctx *Context) printCallResults(info []ipc.CallInfo) {
	for i, inf := range info {
		if inf.Flags&ipc.CallExecuted == 0 {
			continue
		}
		flags := ""
		if inf.Flags&ipc.CallFinished == 0 {
			flags += " unfinished"
		}
		if inf.Flags&ipc.CallBlocked != 0 {
			flags += " blocked"
		}
		if inf.Flags&ipc.CallFaultInjected != 0 {
			flags += " faulted"
		}
		log.Logf(1, "CALL %v: signal %v, coverage %v errno %v%v",
			i, len(inf.Signal), len(inf.Cover), inf.Errno, flags)
	}
}

func (ctx *Context) printHints(p *prog.Prog, info []ipc.CallInfo) {
	ncomps, ncandidates := 0, 0
	for i := range p.Calls {
		if *flagOutput {
			fmt.Printf("call %v:\n", i)
		}
		comps := info[i].Comps
		for v, args := range comps {
			ncomps += len(args)
			if *flagOutput {
				fmt.Printf("comp 0x%x:", v)
				for arg := range args {
					fmt.Printf(" 0x%x", arg)
				}
				fmt.Printf("\n")
			}
		}
		p.MutateWithHints(i, comps, func(p *prog.Prog) {
			ncandidates++
			if *flagOutput {
				log.Logf(1, "PROGRAM:\n%s", p.Serialize())
			}
		})
	}
	log.Logf(0, "ncomps=%v ncandidates=%v", ncomps, ncandidates)
}

func (ctx *Context) dumpCoverage(coverFile string, info []ipc.CallInfo) {
	for i, inf := range info {
		log.Logf(0, "call #%v: signal %v, coverage %v", i, len(inf.Signal), len(inf.Cover))
		if len(inf.Cover) == 0 {
			continue
		}
		buf := new(bytes.Buffer)
		for _, pc := range inf.Cover {
			fmt.Fprintf(buf, "0x%x\n", cover.RestorePC(pc, 0xffffffff))
		}
		err := osutil.WriteFile(fmt.Sprintf("%v.%v", coverFile, i), buf.Bytes())
		if err != nil {
			log.Fatalf("failed to write coverage file: %v", err)
		}
	}
}

func (ctx *Context) getProgramIndex() int {
	ctx.posMu.Lock()
	idx := ctx.pos
	ctx.pos++
	if idx%len(ctx.entries) == 0 && time.Since(ctx.lastPrint) > 5*time.Second {
		log.Logf(0, "executed programs: %v", idx)
		ctx.lastPrint = time.Now()
	}
	ctx.posMu.Unlock()
	return idx
}

func loadPrograms(target *prog.Target, files []string) []*prog.LogEntry {
	var entries []*prog.LogEntry
	for _, fn := range files {
		data, err := ioutil.ReadFile(fn)
		if err != nil {
			log.Fatalf("failed to read log file: %v", err)
		}
		entries = append(entries, target.ParseLog(data)...)
	}
	log.Logf(0, "parsed %v programs", len(entries))
	return entries
}

func createConfig(target *prog.Target, entries []*prog.LogEntry, features *host.Features) (
	*ipc.Config, *ipc.ExecOpts) {
	config, execOpts, err := ipcconfig.Default(target)
	if err != nil {
		log.Fatalf("%v", err)
	}
	if config.Flags&ipc.FlagSignal != 0 {
		execOpts.Flags |= ipc.FlagCollectCover
	}
	if *flagCoverFile != "" {
		config.Flags |= ipc.FlagSignal
		execOpts.Flags |= ipc.FlagCollectCover
		execOpts.Flags &^= ipc.FlagDedupCover
	}
	if *flagHints {
		if execOpts.Flags&ipc.FlagCollectCover != 0 {
			execOpts.Flags ^= ipc.FlagCollectCover
		}
		execOpts.Flags |= ipc.FlagCollectComps
	}
	if *flagFaultCall >= 0 {
		config.Flags |= ipc.FlagEnableFault
		execOpts.Flags |= ipc.FlagInjectFault
		execOpts.FaultCall = *flagFaultCall
		execOpts.FaultNth = *flagFaultNth
	}
	handled := make(map[string]bool)
	for _, entry := range entries {
		for _, call := range entry.P.Calls {
			handled[call.Meta.CallName] = true
		}
	}
	if features[host.FeatureNetworkInjection].Enabled {
		config.Flags |= ipc.FlagEnableTun
	}
	if features[host.FeatureNetworkDevices].Enabled {
		config.Flags |= ipc.FlagEnableNetDev
	}
	return config, execOpts
}
