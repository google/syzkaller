// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// execprog executes a single program or a set of programs
// and optionally prints information about execution.
package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/syzkaller/pkg/cover/backend"
	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/db"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/rpcserver"
	"github.com/google/syzkaller/pkg/tool"
	"github.com/google/syzkaller/pkg/vminfo"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
	"github.com/google/syzkaller/sys/targets"
)

var (
	flagOS          = flag.String("os", runtime.GOOS, "target os")
	flagArch        = flag.String("arch", runtime.GOARCH, "target arch")
	flagType        = flag.String("type", "", "target VM type")
	flagCoverFile   = flag.String("coverfile", "", "write coverage to the file")
	flagRepeat      = flag.Int("repeat", 1, "repeat execution that many times (0 for infinite loop)")
	flagProcs       = flag.Int("procs", 2*runtime.NumCPU(), "number of parallel processes to execute programs")
	flagOutput      = flag.Bool("output", false, "write programs and results to stdout")
	flagHints       = flag.Bool("hints", false, "do a hints-generation run")
	flagEnable      = flag.String("enable", "none", "enable only listed additional features")
	flagDisable     = flag.String("disable", "none", "enable all additional features except listed")
	flagExecutor    = flag.String("executor", "./syz-executor", "path to executor binary")
	flagThreaded    = flag.Bool("threaded", true, "use threaded mode in executor")
	flagSignal      = flag.Bool("cover", false, "collect feedback signals (coverage)")
	flagSandbox     = flag.String("sandbox", "none", "sandbox for fuzzing (none/setuid/namespace/android)")
	flagSandboxArg  = flag.Int("sandbox_arg", 0, "argument for sandbox runner to adjust it via config")
	flagDebug       = flag.Bool("debug", false, "debug output from executor")
	flagSlowdown    = flag.Int("slowdown", 1, "execution slowdown caused by emulation/instrumentation")
	flagUnsafe      = flag.Bool("unsafe", false, "use unsafe program deserialization mode")
	flagGlob        = flag.String("glob", "", "run glob expansion request")
	flagRestartFreq = flag.Int("restart_freq", 0, "restart procs every X executions")

	// The in the stress mode resembles simple unguided fuzzer.
	// This mode can be used as an intermediate step when porting syzkaller to a new OS,
	// or when testing on a machine that is not supported by the vm package (as syz-manager cannot be used).
	// To use this mode one needs to start a VM manually, copy syz-execprog and run it.
	// syz-execprog will execute random programs infinitely until it's stopped or it crashes
	// the kernel underneath. If it's given a corpus of programs, it will alternate between
	// executing random programs and mutated programs from the corpus.
	flagStress   = flag.Bool("stress", false, "enable stress mode (local fuzzer)")
	flagSyscalls = flag.String("syscalls", "", "comma-separated list of enabled syscalls for the stress mode")

	flagGDB = flag.Bool("gdb", false, "start executor under gdb")

	// The following flag is only kept to let syzkaller remain compatible with older execprog versions.
	// In order to test incoming patches or perform bug bisection, syz-ci must use the exact syzkaller
	// version that detected the bug (as descriptions and syntax could've already been changed), and
	// therefore it must be able to invoke older versions of syz-execprog.
	// Unfortunately there's no clean way to drop that flag from newer versions of syz-execprog. If it
	// were false by default, it would be easy - we could modify `instance.ExecprogCmd` only to pass it
	// when it's true - which would never be the case in the newer versions (this is how we got rid of
	// fault injection args). But the collide flag was true by default, so it must be passed by value
	// (-collide=%v). The least kludgy solution is to silently accept this flag also in the newer versions
	// of syzkaller, but do not process it, as there's no such functionality anymore.
	// Note, however, that we do not have to do the same for `syz-prog2c`, as `collide` was there false
	// by default.
	_ = flag.Bool("collide", false, "(DEPRECATED) collide syscalls to provoke data races")
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: execprog [flags] file-with-programs-or-corpus.db+\n")
		flag.PrintDefaults()
		csource.PrintAvailableFeaturesFlags()
	}
	defer tool.Init()()
	target, err := prog.GetTarget(*flagOS, *flagArch)
	if err != nil {
		tool.Fail(err)
	}

	featureFlags, err := csource.ParseFeaturesFlags(*flagEnable, *flagDisable, true)
	if err != nil {
		log.Fatalf("%v", err)
	}
	features := flatrpc.AllFeatures
	for feat := range flatrpc.EnumNamesFeature {
		opt := csource.FlatRPCFeaturesToCSource[feat]
		if opt != "" && !featureFlags[opt].Enabled {
			features &= ^feat
		}
	}

	var requestedSyscalls []int
	if *flagStress {
		syscallList := strings.Split(*flagSyscalls, ",")
		if *flagSyscalls == "" {
			syscallList = nil
		}
		requestedSyscalls, err = mgrconfig.ParseEnabledSyscalls(target, syscallList, nil, mgrconfig.AnyDescriptions)
		if err != nil {
			tool.Failf("failed to parse enabled syscalls: %v", err)
		}
	}

	sandbox, err := flatrpc.SandboxToFlags(*flagSandbox)
	if err != nil {
		tool.Failf("failed to parse sandbox: %v", err)
	}
	env := sandbox
	if *flagDebug {
		env |= flatrpc.ExecEnvDebug
	}
	cover := *flagSignal || *flagHints || *flagCoverFile != ""
	if cover {
		env |= flatrpc.ExecEnvSignal
	}
	var exec flatrpc.ExecFlag
	if *flagThreaded {
		exec |= flatrpc.ExecFlagThreaded
	}
	if *flagCoverFile == "" {
		exec |= flatrpc.ExecFlagDedupCover
	}

	progs := loadPrograms(target, flag.Args())
	if *flagGlob == "" && !*flagStress && len(progs) == 0 {
		flag.Usage()
		os.Exit(1)
	}
	rpcCtx, done := context.WithCancel(context.Background())
	ctx := &Context{
		target:    target,
		done:      done,
		progs:     progs,
		globs:     strings.Split(*flagGlob, ":"),
		rs:        rand.NewSource(time.Now().UnixNano()),
		coverFile: *flagCoverFile,
		output:    *flagOutput,
		signal:    *flagSignal,
		hints:     *flagHints,
		stress:    *flagStress,
		repeat:    *flagRepeat,
		defaultOpts: flatrpc.ExecOpts{
			EnvFlags:   env,
			ExecFlags:  exec,
			SandboxArg: int64(*flagSandboxArg),
		},
	}

	cfg := &rpcserver.LocalConfig{
		Config: rpcserver.Config{
			Config: vminfo.Config{
				Target:     target,
				VMType:     *flagType,
				Features:   features,
				Syscalls:   requestedSyscalls,
				Debug:      *flagDebug,
				Cover:      cover,
				Sandbox:    sandbox,
				SandboxArg: int64(*flagSandboxArg),
			},
			Procs:           *flagProcs,
			Slowdown:        *flagSlowdown,
			ProcRestartFreq: *flagRestartFreq,
		},
		Executor:         *flagExecutor,
		HandleInterrupts: true,
		GDB:              *flagGDB,
		MachineChecked:   ctx.machineChecked,
	}
	if err := rpcserver.RunLocal(rpcCtx, cfg); err != nil {
		tool.Fail(err)
	}
}

type Context struct {
	target      *prog.Target
	done        func()
	progs       []*prog.Prog
	globs       []string
	defaultOpts flatrpc.ExecOpts
	choiceTable *prog.ChoiceTable
	logMu       sync.Mutex
	posMu       sync.Mutex
	rs          rand.Source
	coverFile   string
	output      bool
	signal      bool
	hints       bool
	stress      bool
	repeat      int
	pos         int
	completed   atomic.Uint64
	resultIndex atomic.Int64
	lastPrint   time.Time
}

func (ctx *Context) machineChecked(features flatrpc.Feature, syscalls map[*prog.Syscall]bool) queue.Source {
	if ctx.stress {
		ctx.choiceTable = ctx.target.BuildChoiceTable(ctx.progs, syscalls)
	}
	ctx.defaultOpts.EnvFlags |= csource.FeaturesToFlags(features, nil)
	return queue.DefaultOpts(ctx, ctx.defaultOpts)
}

func (ctx *Context) Next() *queue.Request {
	if *flagGlob != "" {
		idx := int(ctx.resultIndex.Add(1) - 1)
		if idx >= len(ctx.globs) {
			return nil
		}
		req := &queue.Request{
			Type:        flatrpc.RequestTypeGlob,
			GlobPattern: ctx.globs[idx],
		}
		req.OnDone(ctx.doneGlob)
		return req
	}
	var p *prog.Prog
	if ctx.stress {
		p = ctx.createStressProg()
	} else {
		idx := ctx.getProgramIndex()
		if idx < 0 {
			return nil
		}
		p = ctx.progs[idx]
	}
	if ctx.output {
		data := p.Serialize()
		ctx.logMu.Lock()
		log.Logf(0, "executing program:\n%s", data)
		ctx.logMu.Unlock()
	}

	req := &queue.Request{
		Prog: p,
	}
	if ctx.hints {
		req.ExecOpts.ExecFlags |= flatrpc.ExecFlagCollectComps
	} else if ctx.signal || ctx.coverFile != "" {
		req.ExecOpts.ExecFlags |= flatrpc.ExecFlagCollectSignal | flatrpc.ExecFlagCollectCover
	}
	req.OnDone(ctx.Done)
	return req
}

func (ctx *Context) doneGlob(req *queue.Request, res *queue.Result) bool {
	if res.Status == queue.Success {
		files := res.GlobFiles()
		ctx.logMu.Lock()
		fmt.Printf("glob %q expanded to %v files\n", req.GlobPattern, len(files))
		for _, file := range files {
			fmt.Printf("\t%q\n", file)
		}
		ctx.logMu.Unlock()
	} else {
		fmt.Printf("request failed: %v (%v)\n%s\n", res.Status, res.Err, res.Output)
	}
	completed := int(ctx.completed.Add(1))
	if completed >= len(ctx.globs) {
		ctx.done()
	}
	return true
}

func (ctx *Context) Done(req *queue.Request, res *queue.Result) bool {
	if res.Info != nil {
		ctx.printCallResults(res.Info)
		if ctx.hints {
			ctx.printHints(req.Prog, res.Info)
		}
		if ctx.coverFile != "" {
			ctx.dumpCoverage(res.Info)
		}
	}
	completed := int(ctx.completed.Add(1))
	if ctx.repeat > 0 && completed >= len(ctx.progs)*ctx.repeat {
		ctx.done()
	}
	return true
}

func (ctx *Context) printCallResults(info *flatrpc.ProgInfo) {
	for i, inf := range info.Calls {
		if inf.Flags&flatrpc.CallFlagExecuted == 0 {
			continue
		}
		flags := ""
		if inf.Flags&flatrpc.CallFlagFinished == 0 {
			flags += " unfinished"
		}
		if inf.Flags&flatrpc.CallFlagBlocked != 0 {
			flags += " blocked"
		}
		if inf.Flags&flatrpc.CallFlagFaultInjected != 0 {
			flags += " faulted"
		}
		log.Logf(1, "CALL %v: signal %v, coverage %v errno %v%v",
			i, len(inf.Signal), len(inf.Cover), inf.Error, flags)
	}
}

func (ctx *Context) printHints(p *prog.Prog, info *flatrpc.ProgInfo) {
	ncomps, ncandidates := 0, 0
	for i := range p.Calls {
		if ctx.output {
			fmt.Printf("call %v:\n", i)
		}
		comps := make(prog.CompMap)
		for _, cmp := range info.Calls[i].Comps {
			comps.Add(cmp.Pc, cmp.Op1, cmp.Op2, cmp.IsConst)
			if ctx.output {
				fmt.Printf("comp 0x%x ? 0x%x\n", cmp.Op1, cmp.Op2)
			}
		}
		ncomps += len(comps)
		p.MutateWithHints(i, comps, func(p *prog.Prog) bool {
			ncandidates++
			if ctx.output {
				log.Logf(1, "PROGRAM:\n%s", p.Serialize())
			}
			return true
		})
	}
	log.Logf(0, "ncomps=%v ncandidates=%v", ncomps, ncandidates)
}

func (ctx *Context) dumpCallCoverage(coverFile string, info *flatrpc.CallInfo) {
	if info == nil || len(info.Cover) == 0 {
		return
	}
	sysTarget := targets.Get(ctx.target.OS, ctx.target.Arch)
	buf := new(bytes.Buffer)
	for _, pc := range info.Cover {
		prev := backend.PreviousInstructionPC(sysTarget, "", pc)
		fmt.Fprintf(buf, "0x%x\n", prev)
	}
	err := osutil.WriteFile(coverFile, buf.Bytes())
	if err != nil {
		log.Fatalf("failed to write coverage file: %v", err)
	}
}

func (ctx *Context) dumpCoverage(info *flatrpc.ProgInfo) {
	coverFile := fmt.Sprintf("%s_prog%v", ctx.coverFile, ctx.resultIndex.Add(1))
	for i, inf := range info.Calls {
		log.Logf(0, "call #%v: signal %v, coverage %v", i, len(inf.Signal), len(inf.Cover))
		ctx.dumpCallCoverage(fmt.Sprintf("%v.%v", coverFile, i), inf)
	}
	if info.Extra != nil {
		log.Logf(0, "extra: signal %v, coverage %v", len(info.Extra.Signal), len(info.Extra.Cover))
		ctx.dumpCallCoverage(fmt.Sprintf("%v.extra", coverFile), info.Extra)
	}
}

func (ctx *Context) getProgramIndex() int {
	ctx.posMu.Lock()
	defer ctx.posMu.Unlock()
	if ctx.repeat > 0 && ctx.pos >= len(ctx.progs)*ctx.repeat {
		return -1
	}
	idx := ctx.pos % len(ctx.progs)
	if idx == 0 && time.Since(ctx.lastPrint) > 5*time.Second {
		log.Logf(0, "executed programs: %v", ctx.pos)
		ctx.lastPrint = time.Now()
	}
	ctx.pos++
	return idx
}

func (ctx *Context) createStressProg() *prog.Prog {
	ctx.posMu.Lock()
	rnd := rand.New(ctx.rs)
	ctx.posMu.Unlock()
	if len(ctx.progs) == 0 || rnd.Intn(2) == 0 {
		return ctx.target.Generate(rnd, prog.RecommendedCalls, ctx.choiceTable)
	}
	p := ctx.progs[rnd.Intn(len(ctx.progs))].Clone()
	p.Mutate(rnd, prog.RecommendedCalls, ctx.choiceTable, nil, ctx.progs)
	return p
}

func loadPrograms(target *prog.Target, files []string) []*prog.Prog {
	var progs []*prog.Prog
	mode := prog.NonStrict
	if *flagUnsafe {
		mode = prog.NonStrictUnsafe
	}
	for _, fn := range files {
		if corpus, err := db.Open(fn, false); err == nil {
			for _, rec := range corpus.Records {
				p, err := target.Deserialize(rec.Val, mode)
				if err != nil {
					continue
				}
				progs = append(progs, p)
			}
			continue
		}
		data, err := os.ReadFile(fn)
		if err != nil {
			log.Fatalf("failed to read log file: %v", err)
		}
		for _, entry := range target.ParseLog(data, mode) {
			progs = append(progs, entry.P)
		}
	}
	log.Logf(0, "parsed %v programs", len(progs))
	return progs
}
