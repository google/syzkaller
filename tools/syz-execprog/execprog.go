// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// execprog executes a single program or a set of programs
// and optinally prints information about execution.
package main

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"sync"
	"time"

	"github.com/google/syzkaller/cover"
	"github.com/google/syzkaller/ipc"
	"github.com/google/syzkaller/prog"
)

var (
	flagExecutor  = flag.String("executor", "", "path to executor binary")
	flagThreaded  = flag.Bool("threaded", true, "use threaded mode in executor")
	flagCollide   = flag.Bool("collide", true, "collide syscalls to provoke data races")
	flagDebug     = flag.Bool("debug", false, "debug output from executor")
	flagStrace    = flag.Bool("strace", false, "run executor under strace")
	flagCover     = flag.Bool("cover", true, "collect coverage")
	flagCoverFile = flag.String("coverfile", "", "write coverage to the file")
	flagNobody    = flag.Bool("nobody", true, "impersonate into nobody")
	flagDedup     = flag.Bool("dedup", false, "deduplicate coverage in executor")
	flagRepeat    = flag.Int("repeat", 1, "repeat execution that many times (0 for infinite loop)")
	flagProcs     = flag.Int("procs", 1, "number of parallel processes to execute programs")
	flagNoPgid    = flag.Bool("nopgid", false, "don't use setpgid syscall")
	flagTimeout   = flag.Duration("timeout", 10*time.Second, "execution timeout")
)

func main() {
	flag.Parse()
	if len(flag.Args()) == 0 {
		fmt.Fprintf(os.Stderr, "usage: execprog [flags] file-with-programs*\n")
		flag.PrintDefaults()
		os.Exit(1)
	}

	var progs []*prog.Prog
	for _, fn := range flag.Args() {
		progs = append(progs, parseFile(fn)...)
	}
	log.Printf("parsed %v programs", len(progs))
	if len(progs) == 0 {
		return
	}

	var flags uint64
	if *flagThreaded {
		flags |= ipc.FlagThreaded
	}
	if *flagCollide {
		flags |= ipc.FlagCollide
	}
	if *flagDebug {
		flags |= ipc.FlagDebug
	}
	if *flagStrace {
		flags |= ipc.FlagStrace
	}
	if *flagCover || *flagCoverFile != "" {
		flags |= ipc.FlagCover
	}
	if *flagDedup {
		flags |= ipc.FlagDedupCover
	}
	if *flagNobody {
		flags |= ipc.FlagDropPrivs
	}
	if *flagNoPgid {
		flags |= ipc.FlagNoSetpgid
	}

	var wg sync.WaitGroup
	wg.Add(*flagProcs)
	var posMu sync.Mutex
	var pos int
	var lastPrint time.Time
	for p := 0; p < *flagProcs; p++ {
		go func() {
			env, err := ipc.MakeEnv(*flagExecutor, *flagTimeout, flags)
			if err != nil {
				log.Fatalf("failed to create ipc env: %v", err)
			}
			for {
				posMu.Lock()
				idx := pos
				pos++
				if idx%len(progs) == 0 && time.Since(lastPrint) > 5*time.Second {
					log.Printf("executed %v programs\n", idx)
					lastPrint = time.Now()
				}
				posMu.Unlock()
				if *flagRepeat > 0 && idx >= len(progs)**flagRepeat {
					env.Close()
					wg.Done()
					return
				}
				p := progs[idx%len(progs)]
				output, strace, cov, _, failed, hanged, err := env.Exec(p)
				if failed {
					fmt.Printf("BUG: executor-detected bug:\n%s", output)
				}
				if *flagDebug || err != nil {
					fmt.Printf("result: failed=%v hanged=%v err=%v\n\n%s", failed, hanged, err, output)
				}
				if *flagStrace {
					fmt.Printf("strace output:\n%s", strace)
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
							binary.Write(buf, binary.LittleEndian, cover.RestorePC(pc))
						}
						err := ioutil.WriteFile(fmt.Sprintf("%v.%v", *flagCoverFile, i), buf.Bytes(), 0660)
						if err != nil {
							log.Fatalf("failed to write coverage file: %v", err)
						}
					}
				}
			}
		}()
	}
	wg.Wait()
}

func parseFile(fn string) []*prog.Prog {
	logf, err := os.Open(fn)
	if err != nil {
		log.Fatalf("failed to open log file: %v", err)
	}
	log.Printf("parsing log %v", fn)
	s := bufio.NewScanner(logf)
	var cur []byte
	var last *prog.Prog
	var progs []*prog.Prog
	for s.Scan() {
		ln := s.Text()
		tmp := append(cur, ln...)
		tmp = append(tmp, '\n')
		p, err := prog.Deserialize(tmp)
		if err == nil {
			cur = tmp
			last = p
			continue
		}
		if last != nil {
			progs = append(progs, last)
			last = nil
			cur = cur[:0]
		}
	}
	if last != nil {
		progs = append(progs, last)
	}
	return progs
}
