// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"github.com/google/syzkaller/ipc"
	"github.com/google/syzkaller/prog"
)

var (
	flagExecutor = flag.String("executor", "", "path to executor binary")
	flagProg     = flag.String("prog", "", "file with a program to execute")
	flagThreaded = flag.Bool("threaded", false, "use threaded mode in executor")
	flagDebug    = flag.Bool("debug", true, "debug output from executor")
	flagStrace   = flag.Bool("strace", false, "run executor under strace")
	flagCover    = flag.Bool("cover", false, "collect coverage")
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
	if *flagCover {
		flags |= ipc.FlagCover
	}
	env, err := ipc.MakeEnv(*flagExecutor, 3*time.Second, flags)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to create execution environment: %v\n", err)
		os.Exit(1)
	}
	copy(env.In, p.SerializeForExec())
	output, strace, failed, hanged, err := env.Exec()
	fmt.Printf("result: failed=%v hanged=%v err=%v\n\n%s", failed, hanged, err, output)
	if *flagStrace {
		fmt.Printf("strace output:\n%s", strace)
	}
}
