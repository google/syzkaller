// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"net/http"
	_ "net/http/pprof"
	"os"
	"path/filepath"
	"runtime"
	"runtime/debug"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/host"
	"github.com/google/syzkaller/pkg/ipc"
	"github.com/google/syzkaller/pkg/ipc/ipcconfig"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/pkg/tool"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
	"github.com/google/syzkaller/sys/targets"
)

type FuzzerTool struct {
	conn     *flatrpc.Conn
	executor string
	gate     *ipc.Gate
	// TODO: repair triagedCandidates logic, it's broken now.
	triagedCandidates uint32
	timeouts          targets.Timeouts
	leakFrames        []string

	requests  chan *flatrpc.ExecRequest
	signalMu  sync.RWMutex
	maxSignal signal.Signal
}

// Gate size controls how deep in the log the last executed by every proc
// program may be. The intent is to make sure that, given the output log,
// we always understand what was happening.
// Judging by the logs collected on syzbot, 32 should be a reasonable figure.
// It coincides with prog.MaxPids.
const gateSize = prog.MaxPids

// TODO: split into smaller methods.
// nolint: funlen, gocyclo
func main() {
	debug.SetGCPercent(50)

	var (
		flagName      = flag.String("name", "test", "unique name for manager")
		flagOS        = flag.String("os", runtime.GOOS, "target OS")
		flagArch      = flag.String("arch", runtime.GOARCH, "target arch")
		flagManager   = flag.String("manager", "", "manager rpc address")
		flagProcs     = flag.Int("procs", 1, "number of parallel test processes")
		flagTest      = flag.Bool("test", false, "enable image testing mode") // used by syz-ci
		flagPprofPort = flag.Int("pprof_port", 0, "HTTP port for the pprof endpoint (disabled if 0)")
	)
	defer tool.Init()()
	log.Logf(0, "fuzzer started")

	target, err := prog.GetTarget(*flagOS, *flagArch)
	if err != nil {
		log.SyzFatal(err)
	}

	config, execOpts, err := ipcconfig.Default(target)
	if err != nil {
		log.SyzFatalf("failed to create default ipc config: %v", err)
	}
	timeouts := config.Timeouts
	executor := config.Executor
	shutdown := make(chan struct{})
	osutil.HandleInterrupts(shutdown)
	go func() {
		// Handles graceful preemption on GCE.
		<-shutdown
		log.Logf(0, "SYZ-FUZZER: PREEMPTED")
		os.Exit(1)
	}()

	if *flagPprofPort != 0 {
		setupPprofHandler(*flagPprofPort)
	}

	if *flagTest {
		checkArgs := &checkArgs{
			target:         target,
			sandbox:        ipc.FlagsToSandbox(execOpts.EnvFlags),
			ipcConfig:      config,
			ipcExecOpts:    execOpts,
			gitRevision:    prog.GitRevision,
			targetRevision: target.Revision,
		}
		testImage(*flagManager, checkArgs)
		return
	}

	executorArch, executorSyzRevision, executorGitRevision, err := executorVersion(executor)
	if err != nil {
		log.SyzFatalf("failed to run executor version: %v ", err)
	}

	log.Logf(0, "dialing manager at %v", *flagManager)
	conn, err := flatrpc.Dial(*flagManager, timeouts.Scale)
	if err != nil {
		log.SyzFatalf("failed to connect to host: %v ", err)
	}

	log.Logf(1, "connecting to manager...")
	connectReq := &flatrpc.ConnectRequest{
		Name:        *flagName,
		Arch:        executorArch,
		GitRevision: executorGitRevision,
		SyzRevision: executorSyzRevision,
	}
	if err := flatrpc.Send(conn, connectReq); err != nil {
		log.SyzFatal(err)
	}
	connectReplyRaw, err := flatrpc.Recv[flatrpc.ConnectReplyRaw](conn)
	if err != nil {
		log.SyzFatal(err)
	}
	connectReply := connectReplyRaw.UnPack()

	infoReq := &flatrpc.InfoRequest{
		Files: host.ReadFiles(connectReply.Files),
	}
	features, err := host.SetupFeatures(target, executor, connectReply.Features, nil)
	if err != nil {
		infoReq.Error = fmt.Sprintf("failed to setup features: %v ", err)
	}
	infoReq.Features = features
	for _, glob := range connectReply.Globs {
		files, err := filepath.Glob(filepath.FromSlash(glob))
		if err != nil && infoReq.Error == "" {
			infoReq.Error = fmt.Sprintf("failed to read glob %q: %v", glob, err)
		}
		infoReq.Globs = append(infoReq.Globs, &flatrpc.GlobInfo{
			Name:  glob,
			Files: files,
		})
	}
	if err := flatrpc.Send(conn, infoReq); err != nil {
		log.SyzFatal(err)
	}
	infoReplyRaw, err := flatrpc.Recv[flatrpc.InfoReplyRaw](conn)
	if err != nil {
		log.SyzFatal(err)
	}
	infoReply := infoReplyRaw.UnPack()

	if len(infoReply.CoverFilter) != 0 {
		if err := osutil.WriteFile("syz-cover-bitmap", infoReply.CoverFilter); err != nil {
			log.SyzFatalf("failed to write syz-cover-bitmap: %v", err)
		}
	}

	fuzzerTool := &FuzzerTool{
		conn:       conn,
		executor:   executor,
		timeouts:   timeouts,
		leakFrames: connectReply.LeakFrames,

		requests: make(chan *flatrpc.ExecRequest, *flagProcs*4),
	}
	fuzzerTool.filterDataRaceFrames(connectReply.RaceFrames)
	var gateCallback func()
	for _, feat := range features {
		if feat.Id == flatrpc.FeatureLeak && feat.Reason == "" {
			gateCallback = fuzzerTool.leakGateCallback
		}
	}
	fuzzerTool.gate = ipc.NewGate(gateSize, gateCallback)

	log.Logf(0, "starting %v executor processes", *flagProcs)
	for pid := 0; pid < *flagProcs; pid++ {
		startProc(fuzzerTool, pid, config)
	}

	fuzzerTool.handleConn()
}

func (tool *FuzzerTool) leakGateCallback() {
	// Leak checking is very slow so we don't do it while triaging the corpus
	// (otherwise it takes infinity). When we have presumably triaged the corpus
	// (triagedCandidates == 1), we run leak checking bug ignore the result
	// to flush any previous leaks. After that (triagedCandidates == 2)
	// we do actual leak checking and report leaks.
	triagedCandidates := atomic.LoadUint32(&tool.triagedCandidates)
	if triagedCandidates == 0 {
		return
	}
	args := append([]string{"leak"}, tool.leakFrames...)
	timeout := tool.timeouts.NoOutput * 9 / 10
	output, err := osutil.RunCmd(timeout, "", tool.executor, args...)
	if err != nil && triagedCandidates == 2 {
		// If we exit right away, dying executors will dump lots of garbage to console.
		os.Stdout.Write(output)
		fmt.Printf("BUG: leak checking failed\n")
		time.Sleep(time.Hour)
		os.Exit(1)
	}
	if triagedCandidates == 1 {
		atomic.StoreUint32(&tool.triagedCandidates, 2)
	}
}

func (tool *FuzzerTool) filterDataRaceFrames(frames []string) {
	if len(frames) == 0 {
		return
	}
	args := append([]string{"setup_kcsan_filterlist"}, frames...)
	timeout := time.Minute * tool.timeouts.Scale
	output, err := osutil.RunCmd(timeout, "", tool.executor, args...)
	if err != nil {
		log.SyzFatalf("failed to set KCSAN filterlist: %v", err)
	}
	log.Logf(0, "%s", output)
}

func (tool *FuzzerTool) startExecutingCall(progID int64, pid, try int, wait time.Duration) {
	msg := &flatrpc.ExecutorMessage{
		Msg: &flatrpc.ExecutorMessages{
			Type: flatrpc.ExecutorMessagesRawExecuting,
			Value: &flatrpc.ExecutingMessage{
				Id:           progID,
				ProcId:       int32(pid),
				Try:          int32(try),
				WaitDuration: int64(wait),
			},
		},
	}
	if err := flatrpc.Send(tool.conn, msg); err != nil {
		log.SyzFatal(err)
	}
}

func (tool *FuzzerTool) handleConn() {
	for {
		raw, err := flatrpc.Recv[flatrpc.HostMessageRaw](tool.conn)
		if err != nil {
			log.SyzFatal(err)
		}
		switch msg := raw.UnPack().Msg.Value.(type) {
		case *flatrpc.ExecRequest:
			msg.ProgData = slices.Clone(msg.ProgData)
			tool.requests <- msg
		case *flatrpc.SignalUpdate:
			tool.handleSignalUpdate(msg)
		}
	}
}

func (tool *FuzzerTool) diffMaxSignal(info *flatrpc.ProgInfo, mask signal.Signal, maskCall int) {
	tool.signalMu.RLock()
	defer tool.signalMu.RUnlock()
	diffMaxSignal(info, tool.maxSignal, mask, maskCall)
}

func diffMaxSignal(info *flatrpc.ProgInfo, max, mask signal.Signal, maskCall int) {
	if info.Extra != nil {
		info.Extra.Signal = diffCallSignal(info.Extra.Signal, max, mask, -1, maskCall)
	}
	for i := 0; i < len(info.Calls); i++ {
		info.Calls[i].Signal = diffCallSignal(info.Calls[i].Signal, max, mask, i, maskCall)
	}
}

func diffCallSignal(raw []uint64, max, mask signal.Signal, call, maskCall int) []uint64 {
	if mask != nil && call == maskCall {
		return signal.FilterRaw(raw, max, mask)
	}
	return max.DiffFromRaw(raw)
}

func (tool *FuzzerTool) handleSignalUpdate(msg *flatrpc.SignalUpdate) {
	tool.signalMu.Lock()
	defer tool.signalMu.Unlock()
	tool.maxSignal.Subtract(signal.FromRaw(msg.DropMax, 0))
	tool.maxSignal.Merge(signal.FromRaw(msg.NewMax, 0))
}

func setupPprofHandler(port int) {
	// Necessary for pprof handlers.
	go func() {
		err := http.ListenAndServe(fmt.Sprintf("0.0.0.0:%v", port), nil)
		if err != nil {
			log.SyzFatalf("failed to setup a server: %v", err)
		}
	}()
}
