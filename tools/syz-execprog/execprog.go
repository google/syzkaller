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
	"github.com/google/syzkaller/pkg/csource"
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
	flagHints     = flag.Bool("hints", false, "do a hints-generation run")
	flagFaultCall = flag.Int("fault_call", -1, "inject fault into this call (0-based)")
	flagFaultNth  = flag.Int("fault_nth", 0, "inject fault on n-th operation (0-based)")
	flagEnable    = flag.String("enable", "none", "enable only listed additional features")
	flagDisable   = flag.String("disable", "none", "enable all additional features except listed")
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: execprog [flags] file-with-programs+\n")
		flag.PrintDefaults()
		csource.PrintAvailableFeaturesFlags()
	}
	flag.Parse()
	if len(flag.Args()) == 0 {
		flag.Usage()
		os.Exit(1)
	}
	featuresFlags, err := csource.ParseFeaturesFlags(*flagEnable, *flagDisable, true)
	if err != nil {
		log.Fatalf("%v", err)
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
	if *flagOutput {
		for _, feat := range features.Supported() {
			log.Logf(0, "%-24v: %v", feat.Name, feat.Reason)
		}
	}
	config, execOpts := createConfig(target, features, featuresFlags)
	if err = host.Setup(target, features, featuresFlags, config.Executor); err != nil {
		log.Fatal(err)
	}
	var gateCallback func()
	if features[host.FeatureLeak].Enabled {
		gateCallback = func() {
			output, err := osutil.RunCmd(10*time.Minute, "", config.Executor, "leak")
			if err != nil {
				os.Stdout.Write(output)
				os.Exit(1)
			}
		}
	}
	ctx := &Context{
		entries:  entries,
		config:   config,
		execOpts: execOpts,
		gate:     ipc.NewGate(2**flagProcs, gateCallback),
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
	output, info, hanged, err := env.Exec(callOpts, entry.P)
	if ctx.config.Flags&ipc.FlagDebug != 0 || err != nil {
		log.Logf(0, "result: hanged=%v err=%v\n\n%s", hanged, err, output)
	}
	if info != nil {
		ctx.printCallResults(info)
		if *flagHints {
			ctx.printHints(entry.P, info)
		}
		if *flagCoverFile != "" {
			ctx.dumpCoverage(*flagCoverFile, info)
		}
	} else {
		log.Logf(1, "RESULT: no calls executed")
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

func (ctx *Context) printCallResults(info *ipc.ProgInfo) {
	for i, inf := range info.Calls {
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

func (ctx *Context) printHints(p *prog.Prog, info *ipc.ProgInfo) {
	ncomps, ncandidates := 0, 0
	for i := range p.Calls {
		if *flagOutput {
			fmt.Printf("call %v:\n", i)
		}
		comps := info.Calls[i].Comps
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

func (ctx *Context) dumpCallCoverage(coverFile string, info *ipc.CallInfo) {
	if len(info.Cover) == 0 {
		return
	}
	buf := new(bytes.Buffer)
	for _, pc := range info.Cover {
		fmt.Fprintf(buf, "0x%x\n", cover.RestorePC(pc, 0xffffffff))
	}
	err := osutil.WriteFile(coverFile, buf.Bytes())
	if err != nil {
		log.Fatalf("failed to write coverage file: %v", err)
	}
}

func (ctx *Context) dumpCoverage(coverFile string, info *ipc.ProgInfo) {
	for i, inf := range info.Calls {
		log.Logf(0, "call #%v: signal %v, coverage %v", i, len(inf.Signal), len(inf.Cover))
		ctx.dumpCallCoverage(fmt.Sprintf("%v.%v", coverFile, i), &inf)
	}
	log.Logf(0, "extra: signal %v, coverage %v", len(info.Extra.Signal), len(info.Extra.Cover))
	ctx.dumpCallCoverage(fmt.Sprintf("%v.extra", coverFile), &info.Extra)
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

func createConfig(target *prog.Target,
	features *host.Features, featuresFlags csource.Features) (
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
	if features[host.FeatureExtraCoverage].Enabled {
		config.Flags |= ipc.FlagExtraCover
	}
	if *flagFaultCall >= 0 {
		execOpts.Flags |= ipc.FlagInjectFault
		execOpts.FaultCall = *flagFaultCall
		execOpts.FaultNth = *flagFaultNth
	}
	if featuresFlags["tun"].Enabled && features[host.FeatureNetInjection].Enabled {
		config.Flags |= ipc.FlagEnableTun
	}
	if featuresFlags["net_dev"].Enabled && features[host.FeatureNetDevices].Enabled {
		config.Flags |= ipc.FlagEnableNetDev
	}
	if featuresFlags["net_reset"].Enabled {
		config.Flags |= ipc.FlagEnableNetReset
	}
	if featuresFlags["cgroups"].Enabled {
		config.Flags |= ipc.FlagEnableCgroups
	}
	if featuresFlags["close_fds"].Enabled {
		config.Flags |= ipc.FlagEnableCloseFds
	}
	if featuresFlags["devlink_pci"].Enabled && features[host.FeatureDevlinkPCI].Enabled {
		config.Flags |= ipc.FlagEnableDevlinkPCI
	}
	if featuresFlags["vhci"].Enabled && features[host.FeatureVhciInjection].Enabled {
		config.Flags |= ipc.FlagEnableVhciInjection
	}
	return config, execOpts
}
