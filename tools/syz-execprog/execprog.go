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
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/cover/backend"
	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/db"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/host"
	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/ipc/ipcconfig"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/tool"
	"github.com/google/syzkaller/pkg/vminfo"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
	"github.com/google/syzkaller/sys/targets"
)

var (
	flagOS        = flag.String("os", runtime.GOOS, "target os")
	flagArch      = flag.String("arch", runtime.GOARCH, "target arch")
	flagCoverFile = flag.String("coverfile", "", "write coverage to the file")
	flagRepeat    = flag.Int("repeat", 1, "repeat execution that many times (0 for infinite loop)")
	flagProcs     = flag.Int("procs", 2*runtime.NumCPU(), "number of parallel processes to execute programs")
	flagOutput    = flag.Bool("output", false, "write programs and results to stdout")
	flagHints     = flag.Bool("hints", false, "do a hints-generation run")
	flagEnable    = flag.String("enable", "none", "enable only listed additional features")
	flagDisable   = flag.String("disable", "none", "enable all additional features except listed")

	// The in the stress mode resembles simple unguided fuzzer.
	// This mode can be used as an intermediate step when porting syzkaller to a new OS,
	// or when testing on a machine that is not supported by the vm package (as syz-manager cannot be used).
	// To use this mode one needs to start a VM manually, copy syz-execprog and run it.
	// syz-execprog will execute random programs infinitely until it's stopped or it crashes
	// the kernel underneath. If it's given a corpus of programs, it will alternate between
	// executing random programs and mutated programs from the corpus.
	flagStress   = flag.Bool("stress", false, "enable stress mode (local fuzzer)")
	flagSyscalls = flag.String("syscalls", "", "comma-separated list of enabled syscalls for the stress mode")

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
	flagCollide = flag.Bool("collide", false, "(DEPRECATED) collide syscalls to provoke data races")
)

func main() {
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: execprog [flags] file-with-programs-or-corpus.db+\n")
		flag.PrintDefaults()
		csource.PrintAvailableFeaturesFlags()
	}
	defer tool.Init()()
	featuresFlags, err := csource.ParseFeaturesFlags(*flagEnable, *flagDisable, true)
	if err != nil {
		log.Fatalf("%v", err)
	}

	target, err := prog.GetTarget(*flagOS, *flagArch)
	if err != nil {
		log.Fatalf("%v", err)
	}

	progs := loadPrograms(target, flag.Args())
	if !*flagStress && len(progs) == 0 {
		flag.Usage()
		os.Exit(1)
	}
	if *flagCollide {
		log.Logf(0, "note: setting -collide to true is deprecated now and has no effect")
	}
	var requestedSyscalls []int
	if *flagStress {
		syscallList := strings.Split(*flagSyscalls, ",")
		if *flagSyscalls == "" {
			syscallList = nil
		}
		requestedSyscalls, err = mgrconfig.ParseEnabledSyscalls(target, syscallList, nil)
		if err != nil {
			log.Fatalf("failed to parse enabled syscalls: %v", err)
		}
	}
	config, execOpts, syscalls, features := createConfig(target, featuresFlags, requestedSyscalls)
	var gateCallback func()
	if features&flatrpc.FeatureLeak != 0 {
		gateCallback = func() {
			output, err := osutil.RunCmd(10*time.Minute, "", config.Executor, "leak")
			if err != nil {
				os.Stdout.Write(output)
				os.Exit(1)
			}
		}
	}
	var choiceTable *prog.ChoiceTable
	if *flagStress {
		choiceTable = target.BuildChoiceTable(progs, syscalls)
	}
	sysTarget := targets.Get(*flagOS, *flagArch)
	upperBase := getKernelUpperBase(sysTarget)
	ctx := &Context{
		target:      target,
		progs:       progs,
		choiceTable: choiceTable,
		config:      config,
		execOpts:    execOpts,
		gate:        ipc.NewGate(2**flagProcs, gateCallback),
		shutdown:    make(chan struct{}),
		stress:      *flagStress,
		repeat:      *flagRepeat,
		sysTarget:   sysTarget,
		upperBase:   upperBase,
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
	target      *prog.Target
	progs       []*prog.Prog
	choiceTable *prog.ChoiceTable
	config      *ipc.Config
	execOpts    *ipc.ExecOpts
	gate        *ipc.Gate
	shutdown    chan struct{}
	logMu       sync.Mutex
	posMu       sync.Mutex
	stress      bool
	repeat      int
	pos         int
	lastPrint   time.Time
	sysTarget   *targets.Target
	upperBase   uint32
}

func (ctx *Context) run(pid int) {
	env, err := ipc.MakeEnv(ctx.config, pid)
	if err != nil {
		log.Fatalf("failed to create ipc env: %v", err)
	}
	defer env.Close()
	rs := rand.NewSource(time.Now().UnixNano() + int64(pid)*1e12)
	for {
		select {
		case <-ctx.shutdown:
			return
		default:
		}
		if ctx.stress {
			p := ctx.createStressProg(rs)
			ctx.execute(pid, env, p, 0)
		} else {
			idx := ctx.getProgramIndex()
			if ctx.repeat > 0 && idx >= len(ctx.progs)*ctx.repeat {
				return
			}
			p := ctx.progs[idx%len(ctx.progs)]
			ctx.execute(pid, env, p, idx)
		}
	}
}

func (ctx *Context) execute(pid int, env *ipc.Env, p *prog.Prog, progIndex int) {
	// Limit concurrency window.
	ticket := ctx.gate.Enter()
	defer ctx.gate.Leave(ticket)

	callOpts := ctx.execOpts
	if *flagOutput {
		ctx.logProgram(pid, p, callOpts)
	}
	progData, err := p.SerializeForExec()
	if err != nil {
		log.Logf(1, "RESULT: failed to serialize: %v", err)
		return
	}
	// This mimics the syz-fuzzer logic. This is important for reproduction.
	for try := 0; ; try++ {
		output, info, hanged, err := env.ExecProg(callOpts, progData)
		if err != nil {
			if ctx.execOpts.EnvFlags&ipc.FlagDebug != 0 {
				log.Logf(0, "result: hanged=%v err=%v\n\n%s", hanged, err, output)
			}
			if try > 10 {
				log.SyzFatalf("executor %d failed %d times: %v\n%s", pid, try, err, output)
			}
			// Don't print err/output in this case as it may contain "SYZFAIL" and we want to fail yet.
			log.Logf(1, "executor failed, retrying")
			if try > 3 {
				time.Sleep(100 * time.Millisecond)
			}
			continue
		}
		if info != nil {
			ctx.printCallResults(info)
			if *flagHints {
				ctx.printHints(p, info)
			}
			if *flagCoverFile != "" {
				covFile := fmt.Sprintf("%s_prog%d", *flagCoverFile, progIndex)
				ctx.dumpCoverage(covFile, info)
			}
		} else {
			log.Logf(1, "RESULT: no calls executed")
		}
		break
	}
}

func (ctx *Context) logProgram(pid int, p *prog.Prog, callOpts *ipc.ExecOpts) {
	data := p.Serialize()
	ctx.logMu.Lock()
	log.Logf(0, "executing program %v:\n%s", pid, data)
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
		p.MutateWithHints(i, comps, func(p *prog.Prog) bool {
			ncandidates++
			if *flagOutput {
				log.Logf(1, "PROGRAM:\n%s", p.Serialize())
			}
			return true
		})
	}
	log.Logf(0, "ncomps=%v ncandidates=%v", ncomps, ncandidates)
}

func getKernelUpperBase(target *targets.Target) uint32 {
	defaultRet := uint32(0xffffffff)
	if target.OS == targets.Linux {
		// Read the first 8 bytes from /proc/kallsyms.
		f, err := os.Open("/proc/kallsyms")
		if err != nil {
			log.Logf(1, "could not get kernel fixup address: %v", err)
			return defaultRet
		}
		defer f.Close()
		data := make([]byte, 8)
		_, err = f.ReadAt(data, 0)
		if err != nil {
			log.Logf(1, "could not get kernel fixup address: %v", err)
			return defaultRet
		}
		value, err := strconv.ParseUint(string(data), 16, 32)
		if err != nil {
			log.Logf(1, "could not get kernel fixup address: %v", err)
			return defaultRet
		}
		return uint32(value)
	}
	return defaultRet
}

func (ctx *Context) dumpCallCoverage(coverFile string, info *ipc.CallInfo) {
	if len(info.Cover) == 0 {
		return
	}
	buf := new(bytes.Buffer)
	for _, pc := range info.Cover {
		prev := backend.PreviousInstructionPC(ctx.sysTarget, cover.RestorePC(pc, ctx.upperBase))
		fmt.Fprintf(buf, "0x%x\n", prev)
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
	if idx%len(ctx.progs) == 0 && time.Since(ctx.lastPrint) > 5*time.Second {
		log.Logf(0, "executed programs: %v", idx)
		ctx.lastPrint = time.Now()
	}
	ctx.posMu.Unlock()
	return idx
}

func (ctx *Context) createStressProg(rs rand.Source) *prog.Prog {
	rnd := rand.New(rs)
	if len(ctx.progs) == 0 || rnd.Intn(2) == 0 {
		return ctx.target.Generate(rs, prog.RecommendedCalls, ctx.choiceTable)
	}
	p := ctx.progs[rnd.Intn(len(ctx.progs))].Clone()
	p.Mutate(rs, prog.RecommendedCalls, ctx.choiceTable, nil, ctx.progs)
	return p
}

func loadPrograms(target *prog.Target, files []string) []*prog.Prog {
	var progs []*prog.Prog
	for _, fn := range files {
		if corpus, err := db.Open(fn, false); err == nil {
			for _, rec := range corpus.Records {
				p, err := target.Deserialize(rec.Val, prog.NonStrict)
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
		for _, entry := range target.ParseLog(data) {
			progs = append(progs, entry.P)
		}
	}
	log.Logf(0, "parsed %v programs", len(progs))
	return progs
}

func createConfig(target *prog.Target, featuresFlags csource.Features, syscalls []int) (
	*ipc.Config, *ipc.ExecOpts, map[*prog.Syscall]bool, flatrpc.Feature) {
	config, execOpts, err := ipcconfig.Default(target)
	if err != nil {
		log.Fatalf("%v", err)
	}
	if execOpts.EnvFlags&ipc.FlagSignal != 0 {
		execOpts.ExecFlags |= ipc.FlagCollectCover
	}
	if *flagCoverFile != "" {
		execOpts.EnvFlags |= ipc.FlagSignal
		execOpts.ExecFlags |= ipc.FlagCollectCover
		execOpts.ExecFlags &^= ipc.FlagDedupCover
	}
	if *flagHints {
		if execOpts.ExecFlags&ipc.FlagCollectCover != 0 {
			execOpts.ExecFlags ^= ipc.FlagCollectCover
		}
		execOpts.ExecFlags |= ipc.FlagCollectComps
	}
	cfg := &mgrconfig.Config{
		Sandbox:    ipc.FlagsToSandbox(execOpts.EnvFlags),
		SandboxArg: execOpts.SandboxArg,
		Derived: mgrconfig.Derived{
			TargetOS:     target.OS,
			TargetArch:   target.Arch,
			TargetVMArch: target.Arch,
			Target:       target,
			SysTarget:    targets.Get(target.OS, target.Arch),
			Syscalls:     syscalls,
		},
	}
	checker := vminfo.New(cfg)
	fileInfos := host.ReadFiles(checker.RequiredFiles())
	featureInfos, err := host.SetupFeatures(target, config.Executor, flatrpc.AllFeatures, featuresFlags)
	if err != nil {
		log.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go checkerExecutor(ctx, checker, config)

	enabledSyscalls, disabledSyscalls, features, err := checker.Run(fileInfos, featureInfos)
	if err != nil {
		log.Fatal(err)
	}
	if *flagOutput {
		for feat, info := range features {
			log.Logf(0, "%-24v: %v", flatrpc.EnumNamesFeature[feat], info.Reason)
		}
		for c, reason := range disabledSyscalls {
			log.Logf(0, "unsupported syscall: %v: %v", c.Name, reason)
		}
		enabledSyscalls, disabledSyscalls = target.TransitivelyEnabledCalls(enabledSyscalls)
		for c, reason := range disabledSyscalls {
			log.Logf(0, "transitively unsupported: %v: %v", c.Name, reason)
		}
	}
	execOpts.EnvFlags |= ipc.FeaturesToFlags(features.Enabled(), featuresFlags)
	return config, execOpts, enabledSyscalls, features.Enabled()
}

func checkerExecutor(ctx context.Context, source queue.Source, config *ipc.Config) {
	env, err := ipc.MakeEnv(config, 0)
	if err != nil {
		log.Fatalf("failed to create ipc env: %v", err)
	}
	defer env.Close()
	for {
		req := source.Next()
		if req == nil {
			select {
			case <-time.After(time.Second / 100):
			case <-ctx.Done():
				return
			}
			continue
		}
		progData, err := req.Prog.SerializeForExec()
		if err != nil {
			log.Fatalf("failed to serialize %s: %v", req.Prog.Serialize(), err)
		}
		output, info, hanged, err := env.ExecProg(req.ExecOpts, progData)
		res := &queue.Result{
			Status: queue.Success,
			Info:   info,
			Output: output,
		}
		if err != nil {
			res.Status = queue.ExecFailure
			res.Error = err.Error()
		}
		if hanged && err == nil {
			res.Status = queue.ExecFailure
			res.Error = "hanged"
		}
		req.Done(res)
	}
}
