// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// execlog executes all programs from a log (for non-reproducible crashes).
package main

import (
	"bufio"
	"flag"
	"log"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/google/syzkaller/ipc"
	"github.com/google/syzkaller/prog"
)

var (
	flagExecutor = flag.String("executor", "", "path to executor binary")
	flagLog      = flag.String("log", "", "comma-delimited list of log files to execute")
	flagProcs    = flag.Int("procs", 1, "number of parallel processes to execute the log")
)

func main() {
	flag.Parse()
	var progs []*prog.Prog
	for _, fn := range strings.Split(*flagLog, ",") {
		logf, err := os.Open(fn)
		if err != nil {
			log.Fatalf("failed to open log file: %v", err)
		}
		log.Printf("parsing log %v", fn)
		s := bufio.NewScanner(logf)
		var cur []byte
		var last *prog.Prog
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
	}
	log.Printf("parsed %v programs", len(progs))
	if len(progs) == 0 {
		return
	}

	var pos uint32
	for p := 0; p < *flagProcs; p++ {
		go func() {
			env, err := ipc.MakeEnv(*flagExecutor, 5*time.Second, 0)
			if err != nil {
				log.Fatalf("failed to create ipc env: %v", err)
			}
			for {
				idx := int(atomic.AddUint32(&pos, 1) - 1)
				if idx%1000 == 0 {
					log.Printf("executing %v\n", idx)
				}
				_, _, _, _, _, err := env.Exec(progs[idx%len(progs)])
				if err != nil {
					log.Printf("failed to execute program: %v", err)
				}
			}
		}()
	}
	select {}
}
