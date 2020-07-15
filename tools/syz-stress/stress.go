// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"math/rand"
	"os"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/db"
	"github.com/google/syzkaller/pkg/host"
	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/ipc/ipcconfig"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

var (
	flagOS       = flag.String("os", runtime.GOOS, "target os")
	flagArch     = flag.String("arch", runtime.GOARCH, "target arch")
	flagCorpus   = flag.String("corpus", "", "corpus database")
	flagOutput   = flag.Bool("output", false, "print executor output to console")
	flagProcs    = flag.Int("procs", 2*runtime.NumCPU(), "number of parallel processes")
	flagLogProg  = flag.Bool("logprog", false, "print programs before execution")
	flagGenerate = flag.Bool("generate", true, "generate new programs, otherwise only mutate corpus")
	flagSyscalls = flag.String("syscalls", "", "comma-separated list of enabled syscalls")
	flagEnable   = flag.String("enable", "none", "enable only listed additional features")
	flagDisable  = flag.String("disable", "none", "enable all additional features except listed")

	statExec uint64
	gate     *ipc.Gate
)

func main() {
	flag.Usage = func() {
		flag.PrintDefaults()
		csource.PrintAvailableFeaturesFlags()
	}
	flag.Parse()
	featuresFlags, err := csource.ParseFeaturesFlags(*flagEnable, *flagDisable, true)
	if err != nil {
		log.Fatalf("%v", err)
	}
	target, err := prog.GetTarget(*flagOS, *flagArch)
	if err != nil {
		log.Fatalf("%v", err)
	}
	corpus, err := db.ReadCorpus(*flagCorpus, target)
	if err != nil {
		log.Fatalf("failed to read corpus: %v", err)
	}
	log.Logf(0, "parsed %v programs", len(corpus))
	if !*flagGenerate && len(corpus) == 0 {
		log.Fatalf("nothing to mutate (-generate=false and no corpus)")
	}

	features, err := host.Check(target)
	if err != nil {
		log.Fatalf("%v", err)
	}

	var syscalls []string
	if *flagSyscalls != "" {
		syscalls = strings.Split(*flagSyscalls, ",")
	}
	calls := buildCallList(target, syscalls)
	ct := target.BuildChoiceTable(corpus, calls)

	config, execOpts, err := createIPCConfig(target, features, featuresFlags)
	if err != nil {
		log.Fatalf("%v", err)
	}
	if err = host.Setup(target, features, featuresFlags, config.Executor); err != nil {
		log.Fatal(err)
	}
	gate = ipc.NewGate(2**flagProcs, nil)
	for pid := 0; pid < *flagProcs; pid++ {
		pid := pid
		go func() {
			env, err := ipc.MakeEnv(config, pid)
			if err != nil {
				log.Fatalf("failed to create execution environment: %v", err)
			}
			rs := rand.NewSource(time.Now().UnixNano() + int64(pid)*1e12)
			rnd := rand.New(rs)
			for i := 0; ; i++ {
				var p *prog.Prog
				if *flagGenerate && len(corpus) == 0 || i%4 != 0 {
					p = target.Generate(rs, prog.RecommendedCalls, ct)
					execute(pid, env, execOpts, p)
					p.Mutate(rs, prog.RecommendedCalls, ct, corpus)
					execute(pid, env, execOpts, p)
				} else {
					p = corpus[rnd.Intn(len(corpus))].Clone()
					p.Mutate(rs, prog.RecommendedCalls, ct, corpus)
					execute(pid, env, execOpts, p)
					p.Mutate(rs, prog.RecommendedCalls, ct, corpus)
					execute(pid, env, execOpts, p)
				}
			}
		}()
	}
	for range time.NewTicker(5 * time.Second).C {
		log.Logf(0, "executed %v programs", atomic.LoadUint64(&statExec))
	}
}

var outMu sync.Mutex

func execute(pid int, env *ipc.Env, execOpts *ipc.ExecOpts, p *prog.Prog) {
	atomic.AddUint64(&statExec, 1)
	if *flagLogProg {
		ticket := gate.Enter()
		defer gate.Leave(ticket)
		outMu.Lock()
		fmt.Printf("executing program %v\n%s\n", pid, p.Serialize())
		outMu.Unlock()
	}
	output, _, hanged, err := env.Exec(execOpts, p)
	if err != nil {
		fmt.Printf("failed to execute executor: %v\n", err)
	}
	if hanged || err != nil || *flagOutput {
		fmt.Printf("PROGRAM:\n%s\n", p.Serialize())
	}
	if hanged || err != nil || *flagOutput {
		os.Stdout.Write(output)
	}
}

func createIPCConfig(target *prog.Target, features *host.Features, featuresFlags csource.Features) (
	*ipc.Config, *ipc.ExecOpts, error) {
	config, execOpts, err := ipcconfig.Default(target)
	if err != nil {
		return nil, nil, err
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
	return config, execOpts, nil
}

func buildCallList(target *prog.Target, enabled []string) map[*prog.Syscall]bool {
	if *flagOS != runtime.GOOS {
		// This is currently used on akaros, where syz-stress runs on host.
		calls := make(map[*prog.Syscall]bool)
		for _, c := range target.Syscalls {
			calls[c] = true
		}
		return calls
	}
	calls, disabled, err := host.DetectSupportedSyscalls(target, "none")
	if err != nil {
		log.Fatalf("failed to detect host supported syscalls: %v", err)
	}
	if len(enabled) != 0 {
		syscallsIDs, err := mgrconfig.ParseEnabledSyscalls(target, enabled, nil)
		if err != nil {
			log.Fatalf("failed to parse enabled syscalls: %v", err)
		}
		enabledSyscalls := make(map[*prog.Syscall]bool)
		for _, id := range syscallsIDs {
			enabledSyscalls[target.Syscalls[id]] = true
		}
		for c := range calls {
			if !enabledSyscalls[c] {
				delete(calls, c)
			}
		}
		for c := range disabled {
			if !enabledSyscalls[c] {
				delete(disabled, c)
			}
		}
	}
	for c, reason := range disabled {
		log.Logf(0, "unsupported syscall: %v: %v", c.Name, reason)
	}
	calls, disabled = target.TransitivelyEnabledCalls(calls)
	for c, reason := range disabled {
		log.Logf(0, "transitively unsupported: %v: %v", c.Name, reason)
	}
	return calls
}
