// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// execprog executes a single program passed via a flag
// and prints information about execution.
package main

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"github.com/google/syzkaller/cover"
	"github.com/google/syzkaller/ipc"
	"github.com/google/syzkaller/prog"
)

var (
	flagExecutor = flag.String("executor", "", "path to executor binary")
	flagProg     = flag.String("prog", "", "file with a program to execute")
	flagThreaded = flag.Bool("threaded", false, "use threaded mode in executor")
	flagDebug    = flag.Bool("debug", true, "debug output from executor")
	flagStrace   = flag.Bool("strace", false, "run executor under strace")
	flagCover    = flag.String("cover", "", "collect coverage and write to the file")
	flagNobody   = flag.Bool("nobody", true, "impersonate into nobody")
	flagDedup    = flag.Bool("dedup", false, "deduplicate coverage in executor")
	flagTimeout  = flag.Duration("timeout", 5*time.Second, "execution timeout")
)

func main() {
	flag.Parse()
	data, err := ioutil.ReadFile(*flagProg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read prog file: %v\n", err)
		os.Exit(1)
	}
	p, err := prog.Deserialize(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to deserialize the program: %v\n", err)
		os.Exit(1)
	}
	var flags uint64
	if *flagThreaded {
		flags |= ipc.FlagThreaded
	}
	if *flagDebug {
		flags |= ipc.FlagDebug
	}
	if *flagStrace {
		flags |= ipc.FlagStrace
	}
	if *flagCover != "" {
		flags |= ipc.FlagCover
	}
	if *flagDedup {
		flags |= ipc.FlagDedupCover
	}
	if *flagNobody {
		flags |= ipc.FlagDropPrivs
	}
	env, err := ipc.MakeEnv(*flagExecutor, *flagTimeout, flags)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create execution environment: %v\n", err)
		os.Exit(1)
	}
	defer env.Close()
	output, strace, cov, failed, hanged, err := env.Exec(p)
	fmt.Printf("result: failed=%v hanged=%v err=%v\n\n%s", failed, hanged, err, output)
	if *flagStrace {
		fmt.Printf("strace output:\n%s", strace)
	}
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
		err := ioutil.WriteFile(fmt.Sprintf("%v.%v", *flagCover, i), buf.Bytes(), 0660)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to write coverage file: %v\n", err)
			os.Exit(1)
		}
	}
}
