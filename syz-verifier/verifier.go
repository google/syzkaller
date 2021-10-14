// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"errors"
	"fmt"
	"io"
	"math/rand"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/instance"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/vm"
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
		} else {
			fmt.Fprintf(vrf.statsWrite, "%s", vrf.stats.GetTextDescription(totalExecutionTime))
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

// generate will return a newly generated program and its index.
func (vrf *Verifier) generate() (*prog.Prog, int) {
	vrf.progIdx++
	return vrf.target.Generate(vrf.rnd, prog.RecommendedCalls, vrf.choiceTable), vrf.progIdx
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
