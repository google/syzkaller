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
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/instance"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/rpctype"
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
	workdir           string
	crashdir          string
	resultsdir        string
	target            *prog.Target
	runnerBin         string
	executorBin       string
	progGeneratorInit sync.WaitGroup
	choiceTable       *prog.ChoiceTable
	progIdx           int
	addr              string
	srv               *RPCServer
	calls             map[*prog.Syscall]bool
	reasons           map[*prog.Syscall]string
	reportReasons     bool
	stats             *Stats
	statsWrite        io.Writer
	newEnv            bool
	reruns            int

	// We use single queue for every kernel environment.
	tasksMutex     sync.Mutex
	onTaskAdded    *sync.Cond
	kernelEnvTasks [][]*ExecTaskQueue
	taskFactory    *ExecTaskFactory
}

func (vrf *Verifier) Init() {
	vrf.progGeneratorInit.Add(1)

	vrf.onTaskAdded = sync.NewCond(&vrf.tasksMutex)

	vrf.kernelEnvTasks = make([][]*ExecTaskQueue, len(vrf.pools))
	for i := range vrf.kernelEnvTasks {
		vrf.kernelEnvTasks[i] = make([]*ExecTaskQueue, EnvironmentsCount)
		for j := range vrf.kernelEnvTasks[i] {
			vrf.kernelEnvTasks[i][j] = MakeExecTaskQueue()
		}
	}

	srv, err := startRPCServer(vrf)
	if err != nil {
		log.Fatalf("failed to initialise RPC server: %v", err)
	}
	vrf.srv = srv

	vrf.taskFactory = MakeExecTaskFactory()
}

func (vrf *Verifier) StartProgramsAnalysis() {
	go func() {
		vrf.progGeneratorInit.Wait()

		type AnalysisResult struct {
			Diff []*ExecResult
			Prog *prog.Prog
		}

		results := make(chan *AnalysisResult)
		go func() {
			for result := range results {
				if result.Diff != nil {
					vrf.SaveDiffResults(result.Diff, result.Prog)
				}
			}
		}()

		for i := 0; i < 100; i++ {
			go func() {
				for {
					prog := vrf.generate()
					results <- &AnalysisResult{
						vrf.TestProgram(prog),
						prog,
					}
				}
			}()
		}
	}()
}

func (vrf *Verifier) GetRunnerTask(kernel int, existing EnvDescr) *rpctype.ExecTask {
	vrf.tasksMutex.Lock()
	defer vrf.tasksMutex.Unlock()

	for {
		for env := existing; env >= AnyEnvironment; env-- {
			if task, ok := vrf.kernelEnvTasks[kernel][env].PopTask(); ok {
				return task.ToRPC()
			}
		}

		vrf.onTaskAdded.Wait()
	}
}

func (vrf *Verifier) PutExecResult(result *ExecResult) {
	c := vrf.taskFactory.GetExecResultChan(result.ExecTaskID)
	c <- result
}

// TestProgram return the results slice if some exec diff was found.
func (vrf *Verifier) TestProgram(prog *prog.Prog) (result []*ExecResult) {
	steps := []EnvDescr{
		NewEnvironment,
		NewEnvironment,
	}

	defer vrf.stats.TotalProgs.Inc()

	for i, env := range steps {
		stepRes, err := vrf.Run(prog, env)
		if err != nil {
			vrf.stats.ExecErrorProgs.Inc()
			return
		}
		vrf.AddCallsExecutionStat(stepRes, prog)
		if stepRes[0].IsEqual(stepRes[1]) {
			if i != 0 {
				vrf.stats.FlakyProgs.Inc()
			}
			return
		}
		if i == len(steps)-1 {
			vrf.stats.MismatchingProgs.Inc()
			return stepRes
		}
	}
	return
}

// Run sends the program for verification to execution queues and return
// result once it's ready.
// In case of time-out, return (nil, error).
func (vrf *Verifier) Run(prog *prog.Prog, env EnvDescr) (result []*ExecResult, err error) {
	totalKernels := len(vrf.kernelEnvTasks)
	result = make([]*ExecResult, totalKernels)

	wg := sync.WaitGroup{}
	wg.Add(totalKernels)
	for i := 0; i < totalKernels; i++ {
		i := i
		q := vrf.kernelEnvTasks[i][env]

		go func() {
			defer wg.Done()
			task := vrf.taskFactory.MakeExecTask(prog)
			defer vrf.taskFactory.DeleteExecTask(task)

			vrf.tasksMutex.Lock()
			q.PushTask(task)
			vrf.onTaskAdded.Signal()
			vrf.tasksMutex.Unlock()

			result[i] = <-task.ExecResultChan
		}()
	}
	wg.Wait()

	for _, item := range result {
		if item == nil {
			err = errors.New("something went wrong and we exit w/o results")
			return nil, err
		}
		if item.Error != nil {
			err = item.Error
			return nil, err
		}
	}

	return result, nil
}

// SetPrintStatAtSIGINT asks Stats object to report verification
// statistics when an os.Interrupt occurs and Exit().
func (vrf *Verifier) SetPrintStatAtSIGINT() error {
	if vrf.stats == nil {
		return errors.New("verifier.stats is nil")
	}

	osSignalChannel := make(chan os.Signal, 1)
	signal.Notify(osSignalChannel, os.Interrupt)

	go func() {
		<-osSignalChannel
		defer os.Exit(0)

		totalExecutionTime := time.Since(vrf.stats.StartTime.Get()).Minutes()
		if !vrf.stats.MismatchesFound() {
			fmt.Fprint(vrf.statsWrite, "No mismatches occurred until syz-verifier was stopped.")
		} else {
			fmt.Fprintf(vrf.statsWrite, "%s", vrf.stats.GetTextDescription(totalExecutionTime))
		}
	}()

	return nil
}

func (vrf *Verifier) startInstances() {
	for poolID, pi := range vrf.pools {
		totalInstances := pi.pool.Count()
		for vmID := 0; vmID < totalInstances; vmID++ {
			go func(pi *poolInfo, poolID, vmID int) {
				for {
					vrf.createAndManageInstance(pi, poolID, vmID)
				}
			}(pi, poolID, vmID)
		}
	}
}

func (vrf *Verifier) createAndManageInstance(pi *poolInfo, poolID, vmID int) {
	inst, err := pi.pool.Create(vmID)
	if err != nil {
		log.Fatalf("failed to create instance: %v", err)
	}
	defer inst.Close()
	defer vrf.srv.cleanup(poolID, vmID)

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

	cmd := instance.RunnerCmd(runnerBin, fwdAddr, vrf.target.OS, vrf.target.Arch, poolID, 0, false, vrf.newEnv)
	outc, errc, err := inst.Run(pi.cfg.Timeouts.VMRunningTime, vrf.vmStop, cmd)
	if err != nil {
		log.Fatalf("failed to start runner: %v", err)
	}

	inst.MonitorExecution(outc, errc, pi.Reporter, vm.ExitTimeout)

	log.Logf(0, "reboot the VM in pool %d", poolID)
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

// AddCallsExecutionStat ignore all the calls after the first mismatch.
func (vrf *Verifier) AddCallsExecutionStat(results []*ExecResult, program *prog.Prog) {
	rr := CompareResults(results, program)
	for _, cr := range rr.Reports {
		vrf.stats.Calls.IncCallOccurrenceCount(cr.Call)
	}

	for _, cr := range rr.Reports {
		if !cr.Mismatch {
			continue
		}
		vrf.stats.IncCallMismatches(cr.Call)
		for _, state := range cr.States {
			if state0 := cr.States[0]; state0 != state {
				vrf.stats.Calls.AddState(cr.Call, state)
				vrf.stats.Calls.AddState(cr.Call, state0)
			}
		}
		break
	}
}

// SaveDiffResults extract diff and save result on the persistent storage.
func (vrf *Verifier) SaveDiffResults(results []*ExecResult, program *prog.Prog) bool {
	rr := CompareResults(results, program)

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

// generate returns a newly generated program or error.
func (vrf *Verifier) generate() *prog.Prog {
	vrf.progGeneratorInit.Wait()

	rnd := rand.New(rand.NewSource(time.Now().UnixNano() + 1e12))
	return vrf.target.Generate(rnd, prog.RecommendedCalls, vrf.choiceTable)
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
