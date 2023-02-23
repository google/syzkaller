// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Runtest runs syzkaller test programs in sys/*/test/*. Start as:
// $ syz-runtest -config manager.config
// Also see pkg/runtest docs.
package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/instance"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/pkg/runtest"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
	"github.com/google/syzkaller/vm"
)

var (
	flagConfig = flag.String("config", "", "manager config")
	flagDebug  = flag.Bool("debug", false, "debug mode")
	flagTests  = flag.String("tests", "", "prefix to match test file names")
)

func main() {
	flag.Parse()
	cfg, err := mgrconfig.LoadFile(*flagConfig)
	if err != nil {
		log.Fatal(err)
	}
	vmPool, err := vm.Create(cfg, *flagDebug)
	if err != nil {
		log.Fatal(err)
	}
	reporter, err := report.NewReporter(cfg)
	if err != nil {
		log.Fatal(err)
	}
	osutil.MkdirAll(cfg.Workdir)
	mgr := &Manager{
		cfg:              cfg,
		vmPool:           vmPool,
		reporter:         reporter,
		debug:            *flagDebug,
		requests:         make(chan *runtest.RunRequest, 2*vmPool.Count()),
		checkResultC:     make(chan *rpctype.CheckArgs, 1),
		checkResultReady: make(chan bool),
		vmStop:           make(chan bool),
		reqMap:           make(map[int]*runtest.RunRequest),
		lastReq:          make(map[string]int),
	}
	s, err := rpctype.NewRPCServer(cfg.RPC, "Manager", mgr)
	if err != nil {
		log.Fatalf("failed to create rpc server: %v", err)
	}
	mgr.port = s.Addr().(*net.TCPAddr).Port
	go s.Serve()
	var wg sync.WaitGroup
	wg.Add(vmPool.Count())
	fmt.Printf("booting VMs...\n")
	for i := 0; i < vmPool.Count(); i++ {
		i := i
		go func() {
			defer wg.Done()
			name := fmt.Sprintf("vm-%v", i)
			for {
				rep, err := mgr.boot(name, i)
				if err != nil {
					log.Fatal(err)
				}
				if rep == nil {
					return
				}
				if err := mgr.finishRequest(name, rep); err != nil {
					log.Fatal(err)
				}
			}
		}()
	}
	mgr.checkResult = <-mgr.checkResultC
	close(mgr.checkResultReady)
	enabledCalls := make(map[string]map[*prog.Syscall]bool)
	for sandbox, ids := range mgr.checkResult.EnabledCalls {
		calls := make(map[*prog.Syscall]bool)
		for _, id := range ids {
			calls[cfg.Target.Syscalls[id]] = true
		}
		enabledCalls[sandbox] = calls
	}
	for _, feat := range mgr.checkResult.Features.Supported() {
		fmt.Printf("%-24v: %v\n", feat.Name, feat.Reason)
	}
	for sandbox, calls := range enabledCalls {
		if sandbox == "" {
			sandbox = "no"
		}
		fmt.Printf("%-24v: %v calls enabled\n", sandbox+" sandbox", len(calls))
	}
	ctx := &runtest.Context{
		Dir:          filepath.Join(cfg.Syzkaller, "sys", cfg.Target.OS, "test"),
		Target:       cfg.Target,
		Features:     mgr.checkResult.Features,
		EnabledCalls: enabledCalls,
		Requests:     mgr.requests,
		LogFunc:      func(text string) { fmt.Println(text) },
		Verbose:      false,
		Debug:        *flagDebug,
		Tests:        *flagTests,
	}
	err = ctx.Run()
	close(vm.Shutdown)
	wg.Wait()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

type Manager struct {
	cfg              *mgrconfig.Config
	vmPool           *vm.Pool
	reporter         *report.Reporter
	requests         chan *runtest.RunRequest
	checkResult      *rpctype.CheckArgs
	checkResultReady chan bool
	checkResultC     chan *rpctype.CheckArgs
	vmStop           chan bool
	port             int
	debug            bool

	reqMu   sync.Mutex
	reqSeq  int
	reqMap  map[int]*runtest.RunRequest
	lastReq map[string]int
}

func (mgr *Manager) boot(name string, index int) (*report.Report, error) {
	inst, err := mgr.vmPool.Create(index)
	if err != nil {
		return nil, fmt.Errorf("failed to create instance: %v", err)
	}
	defer inst.Close()

	fwdAddr, err := inst.Forward(mgr.port)
	if err != nil {
		return nil, fmt.Errorf("failed to setup port forwarding: %v", err)
	}

	fuzzerBin, err := inst.Copy(mgr.cfg.FuzzerBin)
	if err != nil {
		return nil, fmt.Errorf("failed to copy binary: %v", err)
	}

	// If SyzExecutorCmd is provided, it means that syz-executor is already in
	// the image, so no need to copy it.
	executorBin := mgr.cfg.SysTarget.ExecutorBin
	if executorBin == "" {
		executorBin, err = inst.Copy(mgr.cfg.ExecutorBin)
		if err != nil {
			return nil, fmt.Errorf("failed to copy binary: %v", err)
		}
	}
	args := &instance.FuzzerCmdArgs{
		Fuzzer:    fuzzerBin,
		Executor:  executorBin,
		Name:      name,
		OS:        mgr.cfg.TargetOS,
		Arch:      mgr.cfg.TargetArch,
		FwdAddr:   fwdAddr,
		Sandbox:   mgr.cfg.Sandbox,
		Procs:     mgr.cfg.Procs,
		Verbosity: 0,
		Cover:     mgr.cfg.Cover,
		Debug:     mgr.debug,
		Test:      false,
		Runtest:   true,
		Optional: &instance.OptionalFuzzerArgs{
			Slowdown:   mgr.cfg.Timeouts.Slowdown,
			SandboxArg: mgr.cfg.SandboxArg,
		},
	}
	cmd := instance.FuzzerCmd(args)
	outc, errc, err := inst.Run(time.Hour, mgr.vmStop, cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to run fuzzer: %v", err)
	}
	rep := inst.MonitorExecution(outc, errc, mgr.reporter, vm.ExitNormal)
	return rep, nil
}

func (mgr *Manager) finishRequest(name string, rep *report.Report) error {
	mgr.reqMu.Lock()
	defer mgr.reqMu.Unlock()
	lastReq := mgr.lastReq[name]
	req := mgr.reqMap[lastReq]
	if lastReq == 0 || req == nil {
		return fmt.Errorf("vm crash: %v\n%s\n%s", rep.Title, rep.Report, rep.Output)
	}
	delete(mgr.reqMap, lastReq)
	delete(mgr.lastReq, name)
	req.Err = fmt.Errorf("%v", rep.Title)
	req.Output = rep.Report
	if len(req.Output) == 0 {
		req.Output = rep.Output
	}
	close(req.Done)
	return nil
}

func (mgr *Manager) Connect(a *rpctype.ConnectArgs, r *rpctype.ConnectRes) error {
	r.GitRevision = prog.GitRevision
	r.TargetRevision = mgr.cfg.Target.Revision
	r.AllSandboxes = true
	select {
	case <-mgr.checkResultReady:
		r.CheckResult = mgr.checkResult
	default:
	}
	return nil
}

func (mgr *Manager) Check(a *rpctype.CheckArgs, r *int) error {
	if a.Error != "" {
		log.Fatalf("machine check: %v", a.Error)
	}
	select {
	case mgr.checkResultC <- a:
	default:
	}
	return nil
}

func (mgr *Manager) Poll(a *rpctype.RunTestPollReq, r *rpctype.RunTestPollRes) error {
	req := <-mgr.requests
	if req == nil {
		return nil
	}
	mgr.reqMu.Lock()
	if mgr.lastReq[a.Name] != 0 {
		log.Fatalf("double poll req from %v", a.Name)
	}
	mgr.reqSeq++
	r.ID = mgr.reqSeq
	mgr.reqMap[mgr.reqSeq] = req
	mgr.lastReq[a.Name] = mgr.reqSeq
	mgr.reqMu.Unlock()
	if req.Bin != "" {
		data, err := os.ReadFile(req.Bin)
		if err != nil {
			log.Fatalf("failed to read bin file: %v", err)
		}
		r.Bin = data
		return nil
	}
	r.Prog = req.P.Serialize()
	r.Cfg = req.Cfg
	r.Opts = req.Opts
	r.Repeat = req.Repeat
	return nil
}

func (mgr *Manager) Done(a *rpctype.RunTestDoneArgs, r *int) error {
	mgr.reqMu.Lock()
	lastReq := mgr.lastReq[a.Name]
	if lastReq != a.ID {
		log.Fatalf("wrong done id %v from %v", a.ID, a.Name)
	}
	req := mgr.reqMap[a.ID]
	delete(mgr.reqMap, a.ID)
	delete(mgr.lastReq, a.Name)
	mgr.reqMu.Unlock()
	if req == nil {
		log.Fatalf("got done request for unknown id %v", a.ID)
	}
	req.Output = a.Output
	req.Info = a.Info
	if a.Error != "" {
		req.Err = errors.New(a.Error)
	}
	close(req.Done)
	return nil
}
