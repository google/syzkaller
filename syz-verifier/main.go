// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// package main starts the syz-verifier tool. High-level documentation can be
// found in docs/syz_verfier.md.
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"math/rand"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/instance"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/pkg/rpctype"
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

// RPCServer is a wrapper around the rpc.Server. It communicates with  Runners,
// generates programs and sends complete Results for verification.
type RPCServer struct {
	vrf             *Verifier
	port            int
	mu              sync.Mutex
	cond            *sync.Cond
	pools           map[int]*poolInfo
	progs           map[int]*progInfo
	notChecked      int
	rerunsAvailable *sync.Cond
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
	flag.Var(&cfgs, "configs", "list of kernel-specific comma-sepatated configuration files ")
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

func (vrf *Verifier) startInstances() {
	for idx, pi := range vrf.pools {
		go func(pi *poolInfo, idx int) {
			for { // TODO: implement support for multiple VMs per Pool.
				inst, err := pi.pool.Create(0)
				if err != nil {
					log.Fatalf("failed to create instance: %v", err)
				}
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
				vrf.srv.cleanup(idx, 0)
			}
		}(pi, idx)
	}

	select {}
}

func startRPCServer(vrf *Verifier) (*RPCServer, error) {
	srv := &RPCServer{
		vrf:        vrf,
		pools:      vrf.pools,
		progs:      make(map[int]*progInfo),
		notChecked: len(vrf.pools),
	}
	srv.cond = sync.NewCond(&srv.mu)
	srv.rerunsAvailable = sync.NewCond(&srv.mu)

	s, err := rpctype.NewRPCServer(vrf.addr, "Verifier", srv)
	if err != nil {
		return nil, err
	}

	log.Printf("serving rpc on tcp://%v", s.Addr())
	srv.port = s.Addr().(*net.TCPAddr).Port

	go s.Serve()
	return srv, nil
}

// Connect notifies the RPCServer that a new Runner was started.
func (srv *RPCServer) Connect(a *rpctype.RunnerConnectArgs, r *rpctype.RunnerConnectRes) error {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	pool, vm := a.Pool, a.VM
	srv.pools[pool].runners[vm] = make(runnerProgs)
	r.CheckUnsupportedCalls = !srv.pools[pool].checked
	return nil
}

// UpdateUnsupported communicates to the server the list of system calls not
// supported by the kernel corresponding to this pool and updates the list of
// enabled system calls. This function is called once for each kernel.
// When all kernels have reported the list of unsupported system calls, the
// choice table will be created using only the system calls supported by all
// kernels.
func (srv *RPCServer) UpdateUnsupported(a *rpctype.UpdateUnsupportedArgs, r *int) error {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	if srv.pools[a.Pool].checked {
		return nil
	}
	srv.pools[a.Pool].checked = true
	vrf := srv.vrf

	for _, unsupported := range a.UnsupportedCalls {
		if c := vrf.target.Syscalls[unsupported.ID]; vrf.calls[c] {
			vrf.reasons[c] = unsupported.Reason
		}
	}

	srv.notChecked--
	if srv.notChecked == 0 {
		vrf.finalizeCallSet(os.Stdout)
		vrf.stats = InitStats(vrf.calls, vrf.statsWrite)
		vrf.choiceTable = vrf.target.BuildChoiceTable(nil, vrf.calls)
		srv.cond.Signal()
	}
	return nil
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
		log.Fatal("All enabled system calls are missing dependencies or not" +
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

// NextExchange is called when a Runner requests a new program to execute and,
// potentially, wants to send a new Result to the RPCServer.
func (srv *RPCServer) NextExchange(a *rpctype.NextExchangeArgs, r *rpctype.NextExchangeRes) error {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	var res *Result
	var prog *progInfo
	if a.Info.Calls != nil {
		res = &Result{
			Pool:   a.Pool,
			Hanged: a.Hanged,
			Info:   a.Info,
			RunIdx: a.RunIdx,
		}

		prog = srv.progs[a.ProgIdx]
		if prog == nil {
			// This case can happen if both conditions are true:
			// 1. a Runner calls Verifier.NextExchange, then crashes,
			// its corresponding Pool being the only one that hasn't
			// sent results for the program yet
			// 2.the cleanup call for the crash got the server's mutex before
			// the NextExchange call.
			// As the pool was the only one that hasn't sent the result, the
			// cleanup call has already removed prog from srv.progs by the time
			// the NextExchange call gets the server's mutex, which is why the
			// variable is nil. As the results for this program have already
			// been sent for verification, we discard this one.
			return nil
		}

		delete(srv.pools[a.Pool].runners[a.VM], prog.idx)
		if srv.newResult(res, prog) {
			if srv.vrf.processResults(prog) {
				delete(srv.progs, prog.idx)
			}
		}
	}

	if srv.notChecked > 0 {
		// Runner is blocked until the choice table is created.
		srv.cond.Wait()
	}

	newProg, pi, ri := srv.newProgram(a.Pool, a.VM)
	r.RPCProg = rpctype.RPCProg{Prog: newProg, ProgIdx: pi, RunIdx: ri}
	return nil
}

// newResult is called when a Runner sends a new Result. It returns true if all
// Results from the corresponding programs have been received and they can be
// sent for verification. Otherwise, it returns false.
func (srv *RPCServer) newResult(res *Result, prog *progInfo) bool {
	ri := prog.runIdx
	if prog.res[ri][res.Pool] != nil {
		return false
	}
	prog.res[ri][res.Pool] = res
	prog.received++
	return prog.received == len(srv.pools)
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
			log.Printf("flaky results dected: %d", vrf.stats.FlakyProgs)
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
		log.Printf("failed to write result-%d file, err %v", oldest, err)
	}

	log.Printf("result-%d written successfully", oldest)
	return true
}

func (srv *RPCServer) newRun(p *progInfo) {
	p.runIdx++
	p.received = 0
	p.res[p.runIdx] = make([]*Result, len(srv.pools))
	for _, pool := range srv.pools {
		pool.toRerun = append(pool.toRerun, p)
	}
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

// newProgram returns a new program for the Runner identified by poolIdx and
// vmIdx and the program's index.
func (srv *RPCServer) newProgram(poolIdx, vmIdx int) ([]byte, int, int) {
	pool := srv.pools[poolIdx]

	if len(pool.toRerun) != 0 {
		p := pool.toRerun[0]
		pool.runners[vmIdx][p.idx] = p
		pool.toRerun = pool.toRerun[1:]
		return p.serialized, p.idx, p.runIdx
	}

	if len(pool.progs) == 0 {
		prog, progIdx := srv.vrf.generate()
		pi := &progInfo{
			prog:       prog,
			idx:        progIdx,
			serialized: prog.Serialize(),
			res:        make([][]*Result, srv.vrf.reruns),
		}
		pi.res[0] = make([]*Result, len(srv.pools))
		for _, pool := range srv.pools {
			pool.progs = append(pool.progs, pi)
		}
		srv.progs[progIdx] = pi
	}
	p := pool.progs[0]
	pool.runners[vmIdx][p.idx] = p
	pool.progs = pool.progs[1:]
	return p.serialized, p.idx, p.runIdx
}

// generate will return a newly generated program and its index.
func (vrf *Verifier) generate() (*prog.Prog, int) {
	vrf.progIdx++
	return vrf.target.Generate(vrf.rnd, prog.RecommendedCalls, vrf.choiceTable), vrf.progIdx
}

// cleanup is called when a vm.Instance crashes.
func (srv *RPCServer) cleanup(poolIdx, vmIdx int) {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	progs := srv.pools[poolIdx].runners[vmIdx]

	for _, prog := range progs {
		if srv.newResult(&Result{Pool: poolIdx, Crashed: true}, prog) {
			srv.vrf.processResults(prog)
			delete(srv.progs, prog.idx)
			delete(srv.pools[poolIdx].runners[vmIdx], prog.idx)
			continue
		}
	}
}
