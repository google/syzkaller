// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
package main

import (
	"flag"
	"fmt"
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
	"github.com/google/syzkaller/syz-verifier/verf"
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
	workdir     string
	crashdir    string
	resultsdir  string
	target      *prog.Target
	runnerBin   string
	executorBin string
	choiceTable *prog.ChoiceTable
	rnd         *rand.Rand
	progIdx     int
	addr        string
}

// RPCServer is a wrapper around the rpc.Server. It communicates with  Runners,
// generates programs and sends complete Results for verification.
type RPCServer struct {
	vrf   *Verifier
	port  int
	mu    sync.Mutex
	pools map[int]*poolInfo
	progs map[int]*progInfo
}

// poolInfo contains kernel-specific information for spawning virtual machines
// and reporting crashes. It also keeps track of the Runners executing on
// spawned VMs, what programs have been sent to each Runner and what programs
// have yet to be sent on any of the Runners.
type poolInfo struct {
	cfg      *mgrconfig.Config
	pool     *vm.Pool
	Reporter report.Reporter
	//  vmRunners keeps track of what programs have been sent to each Runner.
	//  There is one Runner executing per VM instance.
	vmRunners map[int][]*progInfo
	// progs stores the programs that haven't been sent to this kernel yet but
	// have been sent to at least one kernel.
	progs []*progInfo
}

type progInfo struct {
	prog       *prog.Prog
	idx        int
	serialized []byte
	res        []*verf.Result
	// left contains the indices of kernels that haven't sent results for this
	// program yet.
	left map[int]bool
}

func main() {
	var cfgs tool.CfgsFlag
	flag.Var(&cfgs, "configs", "list of kernel-specific comma-sepatated configuration files ")
	flagDebug := flag.Bool("debug", false, "dump all VM output to console")
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

	for idx, pi := range pools {
		var err error
		pi.Reporter, err = report.NewReporter(pi.cfg)
		if err != nil {
			log.Fatalf("failed to create reporter for instance-%d: %v", idx, err)
		}
		pi.vmRunners = make(map[int][]*progInfo)
		pi.progs = make([]*progInfo, 0)
	}

	calls := make(map[*prog.Syscall]bool)
	for _, id := range cfg.Syscalls {
		calls[target.Syscalls[id]] = true
	}

	vrf := &Verifier{
		workdir:     workdir,
		crashdir:    crashdir,
		resultsdir:  resultsdir,
		pools:       pools,
		target:      target,
		choiceTable: target.BuildChoiceTable(nil, calls),
		rnd:         rand.New(rand.NewSource(time.Now().UnixNano() + 1e12)),
		runnerBin:   runnerBin,
		executorBin: execBin,
		addr:        addr,
	}

	srv, err := startRPCServer(vrf)
	if err != nil {
		log.Fatalf("failed to initialise RPC server: %v", err)
	}

	for idx, pi := range pools {
		go func(pi *poolInfo, idx int) {
			for { // TODO: implement support for multiple VMs per Pool.
				inst, err := pi.pool.Create(0)
				if err != nil {
					log.Fatalf("failed to create instance: %v", err)
				}

				fwdAddr, err := inst.Forward(srv.port)
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

				cmd := instance.RunnerCmd(runnerBin, fwdAddr, vrf.target.OS, vrf.target.Arch, idx, 0, false, false)
				outc, errc, err := inst.Run(pi.cfg.Timeouts.VMRunningTime, vrf.vmStop, cmd)
				if err != nil {
					log.Fatalf("failed to start runner: %v", err)
				}

				inst.MonitorExecution(outc, errc, pi.Reporter, vm.ExitTimeout)
				srv.cleanup(idx, 0)
			}
		}(pi, idx)
	}

	select {}
}

func startRPCServer(vrf *Verifier) (*RPCServer, error) {
	srv := &RPCServer{
		vrf:   vrf,
		pools: vrf.pools,
		progs: make(map[int]*progInfo),
	}

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
func (srv *RPCServer) Connect(a *rpctype.RunnerConnectArgs, r *int) error {
	srv.mu.Lock()
	defer srv.mu.Unlock()
	pool, vm := a.Pool, a.VM
	srv.pools[pool].vmRunners[vm] = nil
	return nil
}

// NextExchange is called when a Runner requests a new program to execute and,
// potentially, wants to send a new Result to the RPCServer.
func (srv *RPCServer) NextExchange(a *rpctype.NextExchangeArgs, r *rpctype.NextExchangeRes) error {
	srv.mu.Lock()
	defer srv.mu.Unlock()

	if a.Info.Calls != nil {
		res := &verf.Result{
			Pool:   a.Pool,
			Hanged: a.Hanged,
			Info:   a.Info,
		}

		prog := srv.progs[a.ProgIdx]
		if srv.newResult(res, prog) {
			srv.vrf.processResults(prog.res, prog.prog)
			delete(srv.progs, a.ProgIdx)
		}
	}

	prog, pi := srv.newProgram(a.Pool, a.VM)
	r.RPCProg = rpctype.RPCProg{Prog: prog, ProgIdx: pi}
	return nil
}

// newResult is called when a Runner sends a new Result. It returns true if all
// Results from the corresponding programs have been received and they can be
// sent for verification. Otherwise, it returns false.
func (srv *RPCServer) newResult(res *verf.Result, prog *progInfo) bool {
	prog.res = append(prog.res, res)
	delete(prog.left, res.Pool)
	return len(prog.left) == 0
}

// processResults will send a set of complete results for verification and, in
// case differences are found, it will store a result report highlighting those
// in th workdir/results directory. If writing the results fails, it returns an
// error.
func (vrf *Verifier) processResults(res []*verf.Result, prog *prog.Prog) {
	rr := verf.Verify(res, prog)
	if rr == nil {
		return
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
}

func createReport(rr *verf.ResultReport, pools int) []byte {
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
			errno, ok := cr.Errnos[i]
			if !ok {
				// VM crashed so we don't have reports from this pool.
				continue
			}

			data += fmt.Sprintf("\t↳ Pool: %d, Errno: %d, Flag: %d\n", i, errno, cr.Flags[i])
		}

		data += "\n"
	}

	return []byte(data)
}

// newProgram returns a new program for the Runner identified by poolIdx and
// vmIdx and the program's index.
func (srv *RPCServer) newProgram(poolIdx, vmIdx int) ([]byte, int) {
	pool := srv.pools[poolIdx]
	if len(pool.progs) == 0 {
		prog, progIdx := srv.vrf.generate()
		pi := &progInfo{
			prog:       prog,
			idx:        progIdx,
			serialized: prog.Serialize(),
			res:        make([]*verf.Result, 0),
			left:       make(map[int]bool),
		}
		for idx, pool := range srv.pools {
			pool.progs = append(pool.progs, pi)
			pi.left[idx] = true
		}
		srv.progs[progIdx] = pi
	}
	p := pool.progs[0]
	pool.vmRunners[vmIdx] = append(pool.vmRunners[vmIdx], p)
	pool.progs = pool.progs[1:]
	return p.serialized, p.idx
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
	progs := srv.pools[poolIdx].vmRunners[vmIdx]
	delete(srv.pools[poolIdx].vmRunners, vmIdx)
	for idx, prog := range progs {
		delete(prog.left, poolIdx)
		if len(prog.left) == 0 {
			srv.vrf.processResults(prog.res, prog.prog)
			delete(srv.progs, idx)
			continue
		}
	}
}
