// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/prog"
)

var (
	flagThreaded   = flag.Bool("threaded", false, "create threaded program")
	flagCollide    = flag.Bool("collide", false, "create collide program")
	flagRepeat     = flag.Bool("repeat", false, "repeat program infinitely or not")
	flagProcs      = flag.Int("procs", 1, "number of parallel processes")
	flagSandbox    = flag.String("sandbox", "", "sandbox to use (none, setuid, namespace)")
	flagProg       = flag.String("prog", "", "file with program to convert (required)")
	flagFaultCall  = flag.Int("fault_call", -1, "inject fault into this call (0-based)")
	flagFaultNth   = flag.Int("fault_nth", 0, "inject fault on n-th operation (0-based)")
	flagEnableTun  = flag.Bool("tun", false, "set up TUN/TAP interface")
	flagUseTmpDir  = flag.Bool("tmpdir", false, "create a temporary dir and execute inside it")
	flagHandleSegv = flag.Bool("segv", false, "catch and ignore SIGSEGV")
	flagWaitRepeat = flag.Bool("waitrepeat", false, "wait for each repeat attempt")
	flagDebug      = flag.Bool("debug", false, "generate debug printfs")
)

func main() {
	flag.Parse()
	if *flagProg == "" {
		flag.PrintDefaults()
		os.Exit(1)
	}
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
	opts := csource.Options{
		Threaded:   *flagThreaded,
		Collide:    *flagCollide,
		Repeat:     *flagRepeat,
		Procs:      *flagProcs,
		Sandbox:    *flagSandbox,
		Fault:      *flagFaultCall >= 0,
		FaultCall:  *flagFaultCall,
		FaultNth:   *flagFaultNth,
		EnableTun:  *flagEnableTun,
		UseTmpDir:  *flagUseTmpDir,
		HandleSegv: *flagHandleSegv,
		WaitRepeat: *flagWaitRepeat,
		Debug:      *flagDebug,
		Repro:      false,
	}
	src, err := csource.Write(p, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to generate C source: %v\n", err)
		os.Exit(1)
	}
	if formatted, err := csource.Format(src); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
	} else {
		src = formatted
	}
	os.Stdout.Write(src)
}
