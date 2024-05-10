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
	"sync/atomic"
	"time"

	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/host"
	"github.com/google/syzkaller/pkg/instance"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/pkg/rpctype"
	"github.com/google/syzkaller/pkg/runtest"
	"github.com/google/syzkaller/pkg/vminfo"
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
		cfg:                cfg,
		vmPool:             vmPool,
		checker:            vminfo.New(cfg),
		reporter:           reporter,
		debug:              *flagDebug,
		requests:           make(chan *runtest.RunRequest, 4*vmPool.Count()*cfg.Procs),
		checkResultC:       make(chan *rpctype.CheckArgs, 1),
		checkProgsDone:     make(chan bool),
		checkFeaturesReady: make(chan bool),
		vmStop:             make(chan bool),
		reqMap:             make(map[int64]*runtest.RunRequest),
		pending:            make(map[string]map[int64]bool),
	}
	mgr.checkFiles, mgr.checkProgs = mgr.checker.StartCheck()
	mgr.needCheckResults = len(mgr.checkProgs)
	s, err := rpctype.NewRPCServer(cfg.RPC, "Manager", mgr)
	if err != nil {
		log.Fatalf("failed to create rpc server: %v", err)
	}
	mgr.port = s.Addr().(*net.TCPAddr).Port
	go s.Serve()
	var wg sync.WaitGroup
	wg.Add(vmPool.Count())
	fmt.Printf("booting VMs...\n")
	var nameSeq atomic.Uint64
	for i := 0; i < vmPool.Count(); i++ {
		i := i
		go func() {
			defer wg.Done()
			for {
				name := fmt.Sprintf("vm-%v", nameSeq.Add(1))
				rep, err := mgr.boot(name, i)
				if err != nil {
					log.Fatal(err)
				}
				if rep == nil {
					return
				}
				if err := mgr.finishRequests(name, rep); err != nil {
					log.Fatal(err)
				}
			}
		}()
	}
	checkResult := <-mgr.checkResultC
	mgr.checkFeatures = checkResult.Features
	mgr.checkFilesInfo = checkResult.Files
	close(mgr.checkFeaturesReady)
	<-mgr.checkProgsDone
	calls, _, err := mgr.checker.FinishCheck(mgr.checkFilesInfo, mgr.checkResults)
	if err != nil {
		log.Fatalf("failed to detect enabled syscalls: %v", err)
	}
	calls, _ = cfg.Target.TransitivelyEnabledCalls(calls)
	enabledCalls := make(map[string]map[*prog.Syscall]bool)
	// TODO: restore checking/testing of all other sandboxes (we used to test them).
	// Note: syz_emit_ethernet/syz_extract_tcp_res were manually disabled for "" ("no") sandbox,
	// b/c tun is not setup without sandbox.
	enabledCalls[mgr.cfg.Sandbox] = calls
	for _, feat := range checkResult.Features.Supported() {
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
		Features:     checkResult.Features.ToFlatRPC(),
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
	cfg                *mgrconfig.Config
	vmPool             *vm.Pool
	checker            *vminfo.Checker
	checkFiles         []string
	checkFilesInfo     []flatrpc.FileInfo
	checkProgs         []rpctype.ExecutionRequest
	checkResults       []rpctype.ExecutionResult
	needCheckResults   int
	checkProgsDone     chan bool
	reporter           *report.Reporter
	requests           chan *runtest.RunRequest
	checkFeatures      *host.Features
	checkFeaturesReady chan bool
	checkResultC       chan *rpctype.CheckArgs
	vmStop             chan bool
	port               int
	debug              bool

	reqMu   sync.Mutex
	reqSeq  int64
	reqMap  map[int64]*runtest.RunRequest
	pending map[string]map[int64]bool
}

func (mgr *Manager) boot(name string, index int) (*report.Report, error) {
	inst, err := mgr.vmPool.Create(index)
	if err != nil {
		return nil, fmt.Errorf("failed to create instance: %w", err)
	}
	defer inst.Close()

	fwdAddr, err := inst.Forward(mgr.port)
	if err != nil {
		return nil, fmt.Errorf("failed to setup port forwarding: %w", err)
	}

	fuzzerBin, err := inst.Copy(mgr.cfg.FuzzerBin)
	if err != nil {
		return nil, fmt.Errorf("failed to copy binary: %w", err)
	}

	// If SyzExecutorCmd is provided, it means that syz-executor is already in
	// the image, so no need to copy it.
	executorBin := mgr.cfg.SysTarget.ExecutorBin
	if executorBin == "" {
		executorBin, err = inst.Copy(mgr.cfg.ExecutorBin)
		if err != nil {
			return nil, fmt.Errorf("failed to copy binary: %w", err)
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
		Procs:     1,
		Verbosity: 0,
		Cover:     mgr.cfg.Cover,
		Debug:     mgr.debug,
		Test:      false,
		Optional: &instance.OptionalFuzzerArgs{
			Slowdown:   mgr.cfg.Timeouts.Slowdown,
			SandboxArg: mgr.cfg.SandboxArg,
		},
	}
	cmd := instance.FuzzerCmd(args)
	_, rep, err := inst.Run(time.Hour, mgr.reporter, cmd, vm.StopChan(mgr.vmStop))
	if err != nil {
		return nil, fmt.Errorf("failed to run fuzzer: %w", err)
	}
	return rep, nil
}

func (mgr *Manager) finishRequests(name string, rep *report.Report) error {
	mgr.reqMu.Lock()
	defer mgr.reqMu.Unlock()
	for id := range mgr.pending[name] {
		req := mgr.reqMap[id]
		if req == nil {
			return fmt.Errorf("vm crash: %v\n%s\n%s", rep.Title, rep.Report, rep.Output)
		}
		delete(mgr.reqMap, id)
		req.Err = fmt.Errorf("%v", rep.Title)
		req.Output = rep.Report
		if len(req.Output) == 0 {
			req.Output = rep.Output
		}
		close(req.Done)
	}
	delete(mgr.pending, name)
	return nil
}

func (mgr *Manager) Connect(a *rpctype.ConnectArgs, r *rpctype.ConnectRes) error {
	select {
	case <-mgr.checkFeaturesReady:
		r.Features = mgr.checkFeatures
	default:
		r.ReadFiles = append(mgr.checker.RequiredFiles(), mgr.checkFiles...)
		r.ReadGlobs = mgr.cfg.Target.RequiredGlobs()
	}
	return nil
}

func (mgr *Manager) Check(a *rpctype.CheckArgs, r *rpctype.CheckRes) error {
	if a.Error != "" {
		log.Fatalf("machine check: %v", a.Error)
	}
	select {
	case mgr.checkResultC <- a:
	default:
	}
	return nil
}

func (mgr *Manager) ExchangeInfo(a *rpctype.ExchangeInfoRequest, r *rpctype.ExchangeInfoReply) error {
	mgr.reqMu.Lock()
	defer mgr.reqMu.Unlock()

	select {
	case <-mgr.checkProgsDone:
	default:
		mgr.checkResults = append(mgr.checkResults, a.Results...)
		if len(mgr.checkResults) < mgr.needCheckResults {
			numRequests := min(len(mgr.checkProgs), a.NeedProgs)
			r.Requests = mgr.checkProgs[:numRequests]
			mgr.checkProgs = mgr.checkProgs[numRequests:]
		} else {
			close(mgr.checkProgsDone)
		}
		return nil
	}

	if mgr.pending[a.Name] == nil {
		mgr.pending[a.Name] = make(map[int64]bool)
	}
	for _, res := range a.Results {
		if !mgr.pending[a.Name][res.ID] {
			log.Fatalf("runner %v wasn't executing request %v", a.Name, res.ID)
		}
		delete(mgr.pending[a.Name], res.ID)
		req := mgr.reqMap[res.ID]
		if req == nil {
			log.Fatalf("request %v does not exist", res.ID)
		}
		delete(mgr.reqMap, res.ID)
		if req == nil {
			log.Fatalf("got done request for unknown id %v", res.ID)
		}
		req.Output = res.Output
		req.Info = res.Info
		if res.Error != "" {
			req.Err = errors.New(res.Error)
		}
		close(req.Done)
	}
	for i := 0; i < a.NeedProgs; i++ {
		var req *runtest.RunRequest
		select {
		case req = <-mgr.requests:
		default:
		}
		if req == nil {
			break
		}
		mgr.reqSeq++
		mgr.reqMap[mgr.reqSeq] = req
		mgr.pending[a.Name][mgr.reqSeq] = true
		var progData []byte
		var err error
		if req.Bin != "" {
			progData, err = os.ReadFile(req.Bin)
		} else {
			progData, err = req.P.SerializeForExec()
		}
		if err != nil {
			log.Fatal(err)
		}
		r.Requests = append(r.Requests, rpctype.ExecutionRequest{
			ID:           mgr.reqSeq,
			ProgData:     progData,
			ExecOpts:     req.Opts,
			IsBinary:     req.Bin != "",
			ResetState:   req.Bin == "",
			ReturnOutput: true,
			ReturnError:  true,
			Repeat:       req.Repeat,
		})
	}
	return nil
}

func (mgr *Manager) StartExecuting(a *rpctype.ExecutingRequest, r *int) error {
	return nil
}
