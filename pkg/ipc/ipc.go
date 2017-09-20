// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package ipc

import (
	"flag"
	"fmt"
	"time"

	"github.com/google/syzkaller/prog"
)

// Configuration flags for Config.Flags.
const (
	FlagDebug            = uint64(1) << iota // debug output from executor
	FlagSignal                               // collect feedback signals (coverage)
	FlagThreaded                             // use multiple threads to mitigate blocked syscalls
	FlagCollide                              // collide syscalls to provoke data races
	FlagSandboxSetuid                        // impersonate nobody user
	FlagSandboxNamespace                     // use namespaces for sandboxing
	FlagEnableTun                            // initialize and use tun in executor
	FlagEnableFault                          // enable fault injection support
)

// Per-exec flags for ExecOpts.Flags:
const (
	FlagCollectCover = uint64(1) << iota // collect coverage
	FlagDedupCover                       // deduplicate coverage in executor
	FlagInjectFault                      // inject a fault in this execution (see ExecOpts)
	FlagCollectComps                     // collect KCOV comparisons
)

var (
	flagThreaded = flag.Bool("threaded", true, "use threaded mode in executor")
	flagCollide  = flag.Bool("collide", true, "collide syscalls to provoke data races")
	flagSignal   = flag.Bool("cover", true, "collect feedback signals (coverage)")
	flagSandbox  = flag.String("sandbox", "setuid", "sandbox for fuzzing (none/setuid/namespace)")
	flagDebug    = flag.Bool("debug", false, "debug output from executor")
	// Executor protects against most hangs, so we use quite large timeout here.
	// Executor can be slow due to global locks in namespaces and other things,
	// so let's better wait than report false misleading crashes.
	flagTimeout     = flag.Duration("timeout", 1*time.Minute, "execution timeout")
	flagAbortSignal = flag.Int("abort_signal", 0, "initial signal to send to executor in error conditions; upgrades to SIGKILL if executor does not exit")
	flagBufferSize  = flag.Uint64("buffer_size", 0, "internal buffer size (in bytes) for executor output")
)

type ExecOpts struct {
	Flags     uint64
	FaultCall int // call index for fault injection (0-based)
	FaultNth  int // fault n-th operation in the call (0-based)
}

// ExecutorFailure is returned from MakeEnv or from env.Exec when executor terminates by calling fail function.
// This is considered a logical error (a failed assert).
type ExecutorFailure string

func (err ExecutorFailure) Error() string {
	return string(err)
}

// Config is the configuration for Env.
type Config struct {
	// Flags are configuation flags, defined above.
	Flags uint64

	// Timeout is the execution timeout for a single program.
	Timeout time.Duration

	// AbortSignal is the signal to send to the executor in error conditions.
	AbortSignal int

	// BufferSize is the size of the internal buffer for executor output.
	BufferSize uint64
}

func DefaultConfig() (Config, error) {
	var c Config
	if *flagThreaded {
		c.Flags |= FlagThreaded
	}
	if *flagCollide {
		c.Flags |= FlagCollide
	}
	if *flagSignal {
		c.Flags |= FlagSignal
	}
	switch *flagSandbox {
	case "none":
	case "setuid":
		c.Flags |= FlagSandboxSetuid
	case "namespace":
		c.Flags |= FlagSandboxNamespace
	default:
		return Config{}, fmt.Errorf("flag sandbox must contain one of none/setuid/namespace")
	}
	if *flagDebug {
		c.Flags |= FlagDebug
	}
	c.Timeout = *flagTimeout
	c.AbortSignal = *flagAbortSignal
	c.BufferSize = *flagBufferSize
	return c, nil
}

type CallInfo struct {
	Signal []uint32 // feedback signal, filled if FlagSignal is set
	Cover  []uint32 // per-call coverage, filled if FlagSignal is set and cover == true,
	//if dedup == false, then cov effectively contains a trace, otherwise duplicates are removed
	Comps         prog.CompMap // per-call comparison operands
	Errno         int          // call errno (0 if the call was successful)
	FaultInjected bool
}

func GetCompMaps(info []CallInfo) []prog.CompMap {
	compMaps := make([]prog.CompMap, len(info))
	for i, inf := range info {
		compMaps[i] = inf.Comps
	}
	return compMaps
}
