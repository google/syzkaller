// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// execprog executes a single program or a set of programs
// and optinally prints information about execution.
package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/ipc"
	. "github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

var (
	flagOS        = flag.String("os", runtime.GOOS, "target os")
	flagArch      = flag.String("arch", runtime.GOARCH, "target arch")
	flagExecutor  = flag.String("executor", "./syz-executor", "path to executor binary")
	flagCoverFile = flag.String("coverfile", "", "write coverage to the file")
	flagRepeat    = flag.Int("repeat", 1, "repeat execution that many times (0 for infinite loop)")
	flagProcs     = flag.Int("procs", 1, "number of parallel processes to execute programs")
	flagOutput    = flag.String("output", "none", "write programs to none/stdout")
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
		Fatalf("%v", err)
	}

	var entries []*prog.LogEntry
	for _, fn := range flag.Args() {
		data, err := ioutil.ReadFile(fn)
		if err != nil {
			Fatalf("failed to read log file: %v", err)
		}
		entries = target.ParseLog(data)
	}
	Logf(0, "parsed %v programs", len(entries))
	if len(entries) == 0 {
		return
	}

	execOpts := &ipc.ExecOpts{}
	config, err := ipc.DefaultConfig()
	if err != nil {
		Fatalf("%v", err)
	}
	if config.Flags&ipc.FlagSignal != 0 {
		execOpts.Flags |= ipc.FlagCollectCover
	}
	execOpts.Flags |= ipc.FlagDedupCover
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
	if handled["syz_emit_ethernet"] || handled["syz_extract_tcp_res"] {
		config.Flags |= ipc.FlagEnableTun
	}

	var wg sync.WaitGroup
	wg.Add(*flagProcs)
	var posMu, logMu sync.Mutex
	gate := ipc.NewGate(2**flagProcs, nil)
	var pos int
	var lastPrint time.Time
	shutdown := make(chan struct{})
	for p := 0; p < *flagProcs; p++ {
		pid := p
		go func() {
			defer wg.Done()
			env, err := ipc.MakeEnv(*flagExecutor, pid, config)
			if err != nil {
				Fatalf("failed to create ipc env: %v", err)
			}
			defer env.Close()
			for {
				if !func() bool {
					// Limit concurrency window.
					ticket := gate.Enter()
					defer gate.Leave(ticket)

					posMu.Lock()
					idx := pos
					pos++
					if idx%len(entries) == 0 && time.Since(lastPrint) > 5*time.Second {
						Logf(0, "executed programs: %v", idx)
						lastPrint = time.Now()
					}
					posMu.Unlock()
					if *flagRepeat > 0 && idx >= len(entries)**flagRepeat {
						return false
					}
					entry := entries[idx%len(entries)]
					callOpts := execOpts
					if *flagFaultCall == -1 && entry.Fault {
						newOpts := *execOpts
						newOpts.Flags |= ipc.FlagInjectFault
						newOpts.FaultCall = entry.FaultCall
						newOpts.FaultNth = entry.FaultNth
						callOpts = &newOpts
					}
					switch *flagOutput {
					case "stdout":
						strOpts := ""
						if callOpts.Flags&ipc.FlagInjectFault != 0 {
							strOpts = fmt.Sprintf(" (fault-call:%v fault-nth:%v)", callOpts.FaultCall, callOpts.FaultNth)
						}
						data := entry.P.Serialize()
						logMu.Lock()
						Logf(0, "executing program %v%v:\n%s", pid, strOpts, data)
						logMu.Unlock()
					}
					output, info, failed, hanged, err := env.Exec(callOpts, entry.P)
					select {
					case <-shutdown:
						return false
					default:
					}
					if failed {
						fmt.Printf("BUG: executor-detected bug:\n%s", output)
					}
					if config.Flags&ipc.FlagDebug != 0 || err != nil {
						fmt.Printf("result: failed=%v hanged=%v err=%v\n\n%s", failed, hanged, err, output)
					}
					if *flagCoverFile != "" {
						// Coverage is dumped in sanitizer format.
						// github.com/google/sanitizers/tools/sancov command can be used to dump PCs,
						// then they can be piped via addr2line to symbolize.
						for i, inf := range info {
							fmt.Printf("call #%v: signal %v, coverage %v\n", i, len(inf.Signal), len(inf.Cover))
							if len(inf.Cover) == 0 {
								continue
							}
							buf := new(bytes.Buffer)
							binary.Write(buf, binary.LittleEndian, uint64(0xC0BFFFFFFFFFFF64))
							for _, pc := range inf.Cover {
								binary.Write(buf, binary.LittleEndian, cover.RestorePC(pc, 0xffffffff))
							}
							err := osutil.WriteFile(fmt.Sprintf("%v.%v", *flagCoverFile, i), buf.Bytes())
							if err != nil {
								Fatalf("failed to write coverage file: %v", err)
							}
						}
					}
					if *flagHints {
						compMaps := ipc.GetCompMaps(info)
						ncomps, ncandidates := 0, 0
						for i := range entry.P.Calls {
							comps := compMaps[i]
							for v, args := range comps {
								ncomps += len(args)
								if *flagOutput == "stdout" {
									fmt.Printf("comp 0x%x:", v)
									for arg := range args {
										fmt.Printf(" 0x%x", arg)
									}
									fmt.Printf("\n")
								}
							}
							entry.P.MutateWithHints(i, comps, func(p *prog.Prog) {
								ncandidates++
								if *flagOutput == "stdout" {
									fmt.Printf("PROGRAM:\n%s\n", p.Serialize())
								}
							})
						}
						fmt.Printf("ncomps=%v ncandidates=%v\n", ncomps, ncandidates)
					}
					return true
				}() {
					return
				}
			}
		}()
	}

	osutil.HandleInterrupts(shutdown)
	wg.Wait()
}
