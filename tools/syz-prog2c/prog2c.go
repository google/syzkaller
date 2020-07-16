// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"runtime"

	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

var (
	flagOS         = flag.String("os", runtime.GOOS, "target os")
	flagArch       = flag.String("arch", runtime.GOARCH, "target arch")
	flagBuild      = flag.Bool("build", false, "also build the generated program")
	flagThreaded   = flag.Bool("threaded", false, "create threaded program")
	flagCollide    = flag.Bool("collide", false, "create collide program")
	flagRepeat     = flag.Int("repeat", 1, "repeat program that many times (<=0 - infinitely)")
	flagProcs      = flag.Int("procs", 1, "number of parallel processes")
	flagSandbox    = flag.String("sandbox", "", "sandbox to use (none, setuid, namespace)")
	flagProg       = flag.String("prog", "", "file with program to convert (required)")
	flagFaultCall  = flag.Int("fault_call", -1, "inject fault into this call (0-based)")
	flagFaultNth   = flag.Int("fault_nth", 0, "inject fault on n-th operation (0-based)")
	flagHandleSegv = flag.Bool("segv", false, "catch and ignore SIGSEGV")
	flagUseTmpDir  = flag.Bool("tmpdir", false, "create a temporary dir and execute inside it")
	flagTrace      = flag.Bool("trace", false, "trace syscall results")
	flagStrict     = flag.Bool("strict", false, "parse input program in strict mode")
	flagLeak       = flag.Bool("leak", false, "do leak checking")
	flagEnable     = flag.String("enable", "none", "enable only listed additional features")
	flagDisable    = flag.String("disable", "none", "enable all additional features except listed")
)

func main() {
	flag.Usage = func() {
		flag.PrintDefaults()
		csource.PrintAvailableFeaturesFlags()
	}
	flag.Parse()
	if *flagProg == "" {
		flag.Usage()
		os.Exit(1)
	}
	features, err := csource.ParseFeaturesFlags(*flagEnable, *flagDisable, false)
	if err != nil {
		log.Fatalf("%v", err)
	}
	target, err := prog.GetTarget(*flagOS, *flagArch)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v", err)
		os.Exit(1)
	}
	data, err := ioutil.ReadFile(*flagProg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read prog file: %v\n", err)
		os.Exit(1)
	}
	mode := prog.NonStrict
	if *flagStrict {
		mode = prog.Strict
	}
	p, err := target.Deserialize(data, mode)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to deserialize the program: %v\n", err)
		os.Exit(1)
	}
	opts := csource.Options{
		Threaded:      *flagThreaded,
		Collide:       *flagCollide,
		Repeat:        *flagRepeat != 1,
		RepeatTimes:   *flagRepeat,
		Procs:         *flagProcs,
		Sandbox:       *flagSandbox,
		Fault:         *flagFaultCall >= 0,
		FaultCall:     *flagFaultCall,
		FaultNth:      *flagFaultNth,
		Leak:          *flagLeak,
		NetInjection:  features["tun"].Enabled,
		NetDevices:    features["net_dev"].Enabled,
		NetReset:      features["net_reset"].Enabled,
		Cgroups:       features["cgroups"].Enabled,
		BinfmtMisc:    features["binfmt_misc"].Enabled,
		CloseFDs:      features["close_fds"].Enabled,
		KCSAN:         features["kcsan"].Enabled,
		DevlinkPCI:    features["devlink_pci"].Enabled,
		USB:           features["usb"].Enabled,
		VhciInjection: features["vhci"].Enabled,
		UseTmpDir:     *flagUseTmpDir,
		HandleSegv:    *flagHandleSegv,
		Repro:         false,
		Trace:         *flagTrace,
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
	if !*flagBuild {
		return
	}
	bin, err := csource.Build(target, src)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to build C source: %v\n", err)
		os.Exit(1)
	}
	os.Remove(bin)
	fmt.Fprintf(os.Stderr, "binary build OK\n")
}
