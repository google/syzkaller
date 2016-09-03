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
	"log"
	"os"
	"os/signal"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/syzkaller/cover"
	"github.com/google/syzkaller/ipc"
	"github.com/google/syzkaller/prog"
)

var (
	flagExecutor  = flag.String("executor", "./syz-executor", "path to executor binary")
	flagCoverFile = flag.String("coverfile", "", "write coverage to the file")
	flagRepeat    = flag.Int("repeat", 1, "repeat execution that many times (0 for infinite loop)")
	flagProcs     = flag.Int("procs", 1, "number of parallel processes to execute programs")
	flagOutput    = flag.String("output", "none", "write programs to none/stdout")
)

func main() {
	flag.Parse()
	if len(flag.Args()) == 0 {
		fmt.Fprintf(os.Stderr, "usage: execprog [flags] file-with-programs+\n")
		flag.PrintDefaults()
		os.Exit(1)
	}

	var progs []*prog.Prog
	for _, fn := range flag.Args() {
		data, err := ioutil.ReadFile(fn)
		if err != nil {
			log.Fatalf("failed to read log file: %v", err)
		}
		entries := prog.ParseLog(data)
		for _, ent := range entries {
			progs = append(progs, ent.P)
		}
	}
	log.Printf("parsed %v programs", len(progs))
	if len(progs) == 0 {
		return
	}

	flags, timeout, err := ipc.DefaultFlags()
	if err != nil {
		log.Fatalf("%v", err)
	}
	if *flagCoverFile != "" {
		flags |= ipc.FlagCover
		flags &= ^ipc.FlagDedupCover
	}

	var wg sync.WaitGroup
	wg.Add(*flagProcs)
	var posMu, logMu sync.Mutex
	gate := ipc.NewGate(2**flagProcs, nil)
	var pos int
	var lastPrint time.Time
	var shutdown uint32
	for p := 0; p < *flagProcs; p++ {
		pid := p
		go func() {
			defer wg.Done()
			env, err := ipc.MakeEnv(*flagExecutor, timeout, flags)
			if err != nil {
				log.Fatalf("failed to create ipc env: %v", err)
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
					if /*idx%len(progs) == 0 && time.Since(lastPrint) > 5*time.Second*/ (idx % 10) == 0 {
						log.Printf("executed programs: %v", idx)
						lastPrint = time.Now()
					}
					posMu.Unlock()
					if *flagRepeat > 0 && idx >= len(progs)**flagRepeat {
						return false
					}
					p := progs[idx%len(progs)]
					switch *flagOutput {
					case "stdout":
						data := p.Serialize()
						logMu.Lock()
						log.Printf("executing program %v:\n%s", pid, data)
						logMu.Unlock()
					}
					output, cov, _, failed, hanged, err := env.Exec(p)
					if atomic.LoadUint32(&shutdown) != 0 {
						return false
					}
					if failed {
						fmt.Printf("BUG: executor-detected bug:\n%s", output)
					}
					if flags&ipc.FlagDebug != 0 || err != nil {
						fmt.Printf("result: failed=%v hanged=%v err=%v\n\n%s", failed, hanged, err, output)
					}
					if *flagCoverFile != "" {
						// Coverage is dumped in sanitizer format.
						// github.com/google/sanitizers/tools/sancov command can be used to dump PCs,
						// then they can be piped via addr2line to symbolize.
						for i, c := range cov {
							fmt.Printf("call #%v: coverage %v\n", i, len(c))
							if len(c) == 0 {
								continue
							}
							buf := new(bytes.Buffer)
							binary.Write(buf, binary.LittleEndian, uint64(0xC0BFFFFFFFFFFF64))
							for _, pc := range c {
								binary.Write(buf, binary.LittleEndian, cover.RestorePC(pc, 0xffffffff))
							}
							err := ioutil.WriteFile(fmt.Sprintf("%v.%v", *flagCoverFile, i), buf.Bytes(), 0660)
							if err != nil {
								log.Fatalf("failed to write coverage file: %v", err)
							}
						}
					}
					return true
				}() {
					return
				}
			}
		}()
	}

	go func() {
		c := make(chan os.Signal, 2)
		signal.Notify(c, syscall.SIGINT)
		<-c
		log.Printf("shutting down...")
		atomic.StoreUint32(&shutdown, 1)
		<-c
		log.Fatalf("terminating")
	}()

	wg.Wait()
}
