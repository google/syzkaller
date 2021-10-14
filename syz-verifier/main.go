// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// package main starts the syz-verifier tool. High-level documentation can be
// found in docs/syz_verifier.md.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"math/rand"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/instance"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/pkg/tool"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/vm"
)

const (
	maxResultReports = 100
)

// Verifier TODO.
type Verifier struct {
	pools  map[int]*poolInfo
	vmStop chan bool
	// Location of a working directory for all VMs for the syz-verifier process.
	// Outputs here include:
	// - <workdir>/crashes/<OS-Arch>/*: crash output files grouped by OS/Arch
	// - <workdir>/corpus.db: corpus with interesting programs
	// - <workdir>/<OS-Arch>/instance-x: per VM instance temporary files
	// grouped by OS/Arch
	workdir       string
	crashdir      string
	resultsdir    string
	target        *prog.Target
	runnerBin     string
	executorBin   string
	choiceTable   *prog.ChoiceTable
	rnd           *rand.Rand
	progIdx       int
	addr          string
	srv           *RPCServer
	calls         map[*prog.Syscall]bool
	reasons       map[*prog.Syscall]string
	reportReasons bool
	stats         *Stats
	statsWrite    io.Writer
	newEnv        bool
	reruns        int
}



// poolInfo contains kernel-specific information for spawning virtual machines
// and reporting crashes. It also keeps track of the Runners executing on
// spawned VMs, what programs have been sent to each Runner and what programs
// have yet to be sent on any of the Runners.
type poolInfo struct {
	cfg      *mgrconfig.Config
	pool     *vm.Pool
	Reporter *report.Reporter
	//  runners keeps track of what programs have been sent to each Runner.
	//  There is one Runner executing per VM instance.
	runners map[int]runnerProgs
	// progs stores the programs that haven't been sent to this kernel yet but
	// have been sent to at least one other kernel.
	progs []*progInfo
	// toRerun stores the programs that still need to be rerun by this kernel.
	toRerun []*progInfo
	// checked is set to true when the set of system calls not supported on the
	// kernel is known.
	checked bool
}

type progInfo struct {
	prog       *prog.Prog
	idx        int
	serialized []byte
	res        [][]*Result
	// received stores the number of results received for this program.
	received int

	runIdx int
	report *ResultReport
}

type runnerProgs map[int]*progInfo

func main() {
	var cfgs tool.CfgsFlag
	flag.Var(&cfgs, "configs", "[MANDATORY] list of at least two kernel-specific comma-sepatated configuration files")
	flagDebug := flag.Bool("debug", false, "dump all VM output to console")
	flagStats := flag.String("stats", "", "where stats will be written when"+
		"execution of syz-verifier finishes, defaults to stdout")
	flagEnv := flag.Bool("new-env", true, "create a new environment for each program")
	flagReruns := flag.Int("rerun", 3, "number of time program is rerun when a mismatch is found")
	flag.Parse()

	pools := make(map[int]*poolInfo)
	for idx, cfg := range cfgs {
		var err error
		pi := &poolInfo{}
		pi.cfg, err = mgrconfig.LoadFile(cfg)
		if err != nil {
			log.Fatalf("%v", err)
		}
		pi.pool, err = vm.Create(pi.cfg, *flagDebug)
		if err != nil {
			log.Fatalf("%v", err)
		}
		pools[idx] = pi
	}

	if len(pools) < 2 {
		flag.Usage()
		os.Exit(1)
	}

	cfg := pools[0].cfg
	workdir, target, sysTarget, addr := cfg.Workdir, cfg.Target, cfg.SysTarget, cfg.RPC
	for idx := 1; idx < len(pools); idx++ {
		cfg := pools[idx].cfg

		// TODO: pass the configurations that should be the same for all
		// kernels in a default config file in order to avoid this checks and
		// add testing
		if workdir != cfg.Workdir {
			log.Fatalf("working directory mismatch")
		}
		if target != cfg.Target {
			log.Fatalf("target mismatch")
		}
		if sysTarget != cfg.SysTarget {
			log.Fatalf("system target mismatch")
		}
		if addr != pools[idx].cfg.RPC {
			log.Fatalf("tcp address mismatch")
		}
	}

	exe := sysTarget.ExeExtension
	runnerBin := filepath.Join(cfg.Syzkaller, "bin", target.OS+"_"+target.Arch, "syz-runner"+exe)
	if !osutil.IsExist(runnerBin) {
		log.Fatalf("bad syzkaller config: can't find %v", runnerBin)
	}
	execBin := cfg.ExecutorBin
	if !osutil.IsExist(execBin) {
		log.Fatalf("bad syzkaller config: can't find %v", execBin)
	}

	crashdir := filepath.Join(workdir, "crashes")
	osutil.MkdirAll(crashdir)
	for idx := range pools {
		OS, Arch := target.OS, target.Arch
		targetPath := OS + "-" + Arch + "-" + strconv.Itoa(idx)
		osutil.MkdirAll(filepath.Join(workdir, targetPath))
		osutil.MkdirAll(filepath.Join(crashdir, targetPath))
	}

	resultsdir := filepath.Join(workdir, "results")
	osutil.MkdirAll(resultsdir)

	var sw io.Writer
	var err error
	if *flagStats == "" {
		sw = os.Stdout
	} else {
		statsFile := filepath.Join(workdir, *flagStats)
		sw, err = os.Create(statsFile)
		if err != nil {
			log.Fatalf("failed to create stats output file: %v", err)
		}
	}

	for idx, pi := range pools {
		var err error
		pi.Reporter, err = report.NewReporter(pi.cfg)
		if err != nil {
			log.Fatalf("failed to create reporter for instance-%d: %v", idx, err)
		}
		pi.runners = make(map[int]runnerProgs)
	}

	calls := make(map[*prog.Syscall]bool)

	for _, id := range cfg.Syscalls {
		c := target.Syscalls[id]
		calls[c] = true
	}

	vrf := &Verifier{
		workdir:       workdir,
		crashdir:      crashdir,
		resultsdir:    resultsdir,
		pools:         pools,
		target:        target,
		calls:         calls,
		reasons:       make(map[*prog.Syscall]string),
		rnd:           rand.New(rand.NewSource(time.Now().UnixNano() + 1e12)),
		runnerBin:     runnerBin,
		executorBin:   execBin,
		addr:          addr,
		reportReasons: len(cfg.EnabledSyscalls) != 0 || len(cfg.DisabledSyscalls) != 0,
		statsWrite:    sw,
		newEnv:        *flagEnv,
		reruns:        *flagReruns,
	}

	vrf.srv, err = startRPCServer(vrf)
	if err != nil {
		log.Fatalf("failed to initialise RPC server: %v", err)
	}

	vrf.startInstances()
}

// SetPrintStatAtSIGINT asks Stats object to report verification
// statistics when an os.Interrupt occurs and Exit().
func (vrf *Verifier) SetPrintStatAtSIGINT() error {
	if vrf.stats == nil {
		return errors.New("verifier.stats is nil")
	}

	osSignalChannel := make(chan os.Signal)
	signal.Notify(osSignalChannel, os.Interrupt)

	go func() {
		<-osSignalChannel
		defer os.Exit(0)

		totalExecutionTime := time.Since(vrf.stats.StartTime).Minutes()
		if vrf.stats.TotalMismatches < 0 {
			fmt.Fprint(vrf.statsWrite, "No mismatches occurred until syz-verifier was stopped.")
		}else{
			fmt.Fprintf(vrf.statsWrite, vrf.stats.GetTextDescription(totalExecutionTime))
		}
	}()

	return nil
}

func (vrf *Verifier) startInstances() {
	for idx, pi := range vrf.pools {
		go func(pi *poolInfo, idx int) {
			for {
				// TODO: implement support for multiple VMs per Pool.

				vrf.createAndManageInstance(pi, idx)
			}
		}(pi, idx)
	}

	select {}
}

func (vrf *Verifier) createAndManageInstance(pi *poolInfo, idx int) {
	inst, err := pi.pool.Create(0)
	if err != nil {
		log.Fatalf("failed to create instance: %v", err)
	}
	defer inst.Close()
	defer vrf.srv.cleanup(idx, 0)

	fwdAddr, err := inst.Forward(vrf.srv.port)
	if err != nil {
		log.Fatalf("failed to set up port forwarding: %v", err)
	}

	runnerBin, err := inst.Copy(vrf.runnerBin)
	if err != nil {
		log.Fatalf(" failed to copy runner binary: %v", err)
	}
	_, err = inst.Copy(vrf.executorBin)
	if err != nil {
		log.Fatalf("failed to copy executor binary: %v", err)
	}

	cmd := instance.RunnerCmd(runnerBin, fwdAddr, vrf.target.OS, vrf.target.Arch, idx, 0, false, false, vrf.newEnv)
	outc, errc, err := inst.Run(pi.cfg.Timeouts.VMRunningTime, vrf.vmStop, cmd)
	if err != nil {
		log.Fatalf("failed to start runner: %v", err)
	}

	inst.MonitorExecution(outc, errc, pi.Reporter, vm.ExitTimeout)

	log.Logf(0, "reboot the VM in pool %d", idx)
}

// finalizeCallSet removes the system calls that are not supported from the set
// of enabled system calls and reports the reason to the io.Writer (either
// because the call is not supported by one of the kernels or because the call
// is missing some transitive dependencies). The resulting set of system calls
// will be used to build the prog.ChoiceTable.
func (vrf *Verifier) finalizeCallSet(w io.Writer) {
	for c := range vrf.reasons {
		delete(vrf.calls, c)
	}

	// Find and report to the user all the system calls that need to be
	// disabled due to missing dependencies.
	_, disabled := vrf.target.TransitivelyEnabledCalls(vrf.calls)
	for c, reason := range disabled {
		vrf.reasons[c] = reason
		delete(vrf.calls, c)
	}

	if len(vrf.calls) == 0 {
		log.Logf(0, "All enabled system calls are missing dependencies or not"+
			" supported by some kernels, exiting syz-verifier.")
	}

	if !vrf.reportReasons {
		return
	}

	fmt.Fprintln(w, "The following calls have been disabled:")
	for c, reason := range vrf.reasons {
		fmt.Fprintf(w, "\t%v: %v\n", c.Name, reason)
	}
}

// processResults will send a set of complete results for verification and, in
// case differences are found, it will start the rerun process for the program
// (if reruns are enabled). If every rerun produces the same results, the result
// report will be printed to persistent storage. Otherwise, the program is
// discarded as flaky.
func (vrf *Verifier) processResults(prog *progInfo) bool {
	// TODO: Simplify this if clause.
	if prog.runIdx == 0 {
		vrf.stats.TotalProgs++
		prog.report = Verify(prog.res[0], prog.prog, vrf.stats)
		if prog.report == nil {
			return true
		}
	} else {
		if !VerifyRerun(prog.res[prog.runIdx], prog.report) {
			vrf.stats.FlakyProgs++
			log.Logf(0, "flaky results detected: %d", vrf.stats.FlakyProgs)
			return true
		}
	}

	if prog.runIdx < vrf.reruns-1 {
		vrf.srv.newRun(prog)
		return false
	}

	rr := prog.report
	vrf.stats.MismatchingProgs++

	for _, cr := range rr.Reports {
		if !cr.Mismatch {
			break
		}
		vrf.stats.Calls[cr.Call].Mismatches++
		vrf.stats.TotalMismatches++
		for _, state := range cr.States {
			if state0 := cr.States[0]; state0 != state {
				vrf.stats.Calls[cr.Call].States[state] = true
				vrf.stats.Calls[cr.Call].States[state0] = true
			}
		}
	}

	oldest := 0
	var oldestTime time.Time
	for i := 0; i < maxResultReports; i++ {
		info, err := os.Stat(filepath.Join(vrf.resultsdir, fmt.Sprintf("result-%d", i)))
		if err != nil {
			// There are only i-1 report files so the i-th one
			// can be created.
			oldest = i
			break
		}

		// Otherwise, search for the oldest report file to
		// overwrite as newer result reports are more useful.
		if oldestTime.IsZero() || info.ModTime().Before(oldestTime) {
			oldest = i
			oldestTime = info.ModTime()
		}
	}

	err := osutil.WriteFile(filepath.Join(vrf.resultsdir,
		fmt.Sprintf("result-%d", oldest)), createReport(rr, len(vrf.pools)))
	if err != nil {
		log.Logf(0, "failed to write result-%d file, err %v", oldest, err)
	}

	log.Logf(0, "result-%d written successfully", oldest)
	return true
}

func createReport(rr *ResultReport, pools int) []byte {
	calls := strings.Split(rr.Prog, "\n")
	calls = calls[:len(calls)-1]

	data := "ERRNO mismatches found for program:\n\n"
	for idx, cr := range rr.Reports {
		tick := "[=]"
		if cr.Mismatch {
			tick = "[!]"
		}
		data += fmt.Sprintf("%s %s\n", tick, calls[idx])

		// Ensure results are ordered by pool index.
		for i := 0; i < pools; i++ {
			state := cr.States[i]
			data += fmt.Sprintf("\t↳ Pool: %d, %s\n", i, state)
		}

		data += "\n"
	}

	return []byte(data)
}

// generate will return a newly generated program and its index.
func (vrf *Verifier) generate() (*prog.Prog, int) {
	vrf.progIdx++
	return vrf.target.Generate(vrf.rnd, prog.RecommendedCalls, vrf.choiceTable), vrf.progIdx
}