// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package rpcserver

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"slices"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/stat"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
	"github.com/google/syzkaller/vm/dispatcher"
)

type Runner struct {
	id            int
	source        *queue.Distributor
	procs         int
	cover         bool
	coverEdges    bool
	filterSignal  bool
	debug         bool
	debugTimeouts bool
	sysTarget     *targets.Target
	stats         *runnerStats
	finished      chan bool
	injectExec    chan<- bool
	infoc         chan chan []byte
	canonicalizer *cover.CanonicalizerInstance
	nextRequestID int64
	requests      map[int64]*queue.Request
	executing     map[int64]bool
	lastExec      *LastExecuting
	updInfo       dispatcher.UpdateInfo
	resultCh      chan error

	// The mutex protects all the fields below.
	mu          sync.Mutex
	conn        *flatrpc.Conn
	stopped     bool
	machineInfo []byte
}

type runnerStats struct {
	statExecs              *stat.Val
	statExecRetries        *stat.Val
	statExecutorRestarts   *stat.Val
	statExecBufferTooSmall *stat.Val
	statNoExecRequests     *stat.Val
	statNoExecDuration     *stat.Val
}

type handshakeConfig struct {
	VMLess     bool
	Timeouts   targets.Timeouts
	LeakFrames []string
	RaceFrames []string
	Files      []string
	Globs      []string
	Features   flatrpc.Feature

	// Callback() is called in the middle of the handshake process.
	// The return arguments are the coverage filter and the (possible) error.
	Callback func(*flatrpc.InfoRequestRawT) (handshakeResult, error)
}

type handshakeResult struct {
	CovFilter     []uint64
	MachineInfo   []byte
	Canonicalizer *cover.CanonicalizerInstance
}

func (runner *Runner) Handshake(conn *flatrpc.Conn, cfg *handshakeConfig) error {
	if runner.updInfo != nil {
		runner.updInfo(func(info *dispatcher.Info) {
			info.Status = "handshake"
		})
	}

	connectReply := &flatrpc.ConnectReply{
		Debug:            runner.debug,
		Cover:            runner.cover,
		CoverEdges:       runner.coverEdges,
		Kernel64Bit:      runner.sysTarget.PtrSize == 8,
		Procs:            int32(runner.procs),
		Slowdown:         int32(cfg.Timeouts.Slowdown),
		SyscallTimeoutMs: int32(cfg.Timeouts.Syscall / time.Millisecond),
		ProgramTimeoutMs: int32(cfg.Timeouts.Program / time.Millisecond),
		LeakFrames:       cfg.LeakFrames,
		RaceFrames:       cfg.RaceFrames,
		Files:            cfg.Files,
		Globs:            cfg.Globs,
		Features:         cfg.Features,
	}
	if err := flatrpc.Send(conn, connectReply); err != nil {
		return err
	}
	infoReq, err := flatrpc.Recv[*flatrpc.InfoRequestRaw](conn)
	if err != nil {
		return err
	}
	ret, err := cfg.Callback(infoReq)
	if err != nil {
		return err
	}
	infoReply := &flatrpc.InfoReply{
		CoverFilter: ret.CovFilter,
	}
	if err := flatrpc.Send(conn, infoReply); err != nil {
		return err
	}
	runner.mu.Lock()
	runner.conn = conn
	runner.machineInfo = ret.MachineInfo
	runner.canonicalizer = ret.Canonicalizer
	runner.mu.Unlock()

	if runner.updInfo != nil {
		runner.updInfo(func(info *dispatcher.Info) {
			info.MachineInfo = runner.MachineInfo
			info.DetailedStatus = runner.QueryStatus
		})
	}
	return nil
}

func (runner *Runner) ConnectionLoop() error {
	if runner.updInfo != nil {
		runner.updInfo(func(info *dispatcher.Info) {
			info.Status = "executing"
		})
	}

	runner.mu.Lock()
	stopped := runner.stopped
	if !stopped {
		runner.finished = make(chan bool)
	}
	runner.mu.Unlock()

	if stopped {
		// The instance was shut down in between, see the shutdown code.
		return nil
	}
	defer close(runner.finished)

	var infoc chan []byte
	defer func() {
		if infoc != nil {
			infoc <- []byte("VM has crashed")
		}
	}()
	for {
		if infoc == nil {
			select {
			case infoc = <-runner.infoc:
				err := runner.sendStateRequest()
				if err != nil {
					return err
				}
			default:
			}
		}
		for len(runner.requests)-len(runner.executing) < 2*runner.procs {
			req := runner.source.Next(runner.id)
			if req == nil {
				break
			}
			if err := runner.sendRequest(req); err != nil {
				return err
			}
		}
		if len(runner.requests) == 0 {
			if !runner.Alive() {
				return nil
			}
			// The runner has no new requests, so don't wait to receive anything from it.
			time.Sleep(10 * time.Millisecond)
			continue
		}
		raw, err := wrappedRecv[*flatrpc.ExecutorMessageRaw](runner)
		if err != nil {
			return err
		}
		if raw.Msg == nil || raw.Msg.Value == nil {
			return errors.New("received no message")
		}
		switch msg := raw.Msg.Value.(type) {
		case *flatrpc.ExecutingMessage:
			err = runner.handleExecutingMessage(msg)
		case *flatrpc.ExecResult:
			err = runner.handleExecResult(msg)
		case *flatrpc.StateResult:
			buf := new(bytes.Buffer)
			fmt.Fprintf(buf, "pending requests on the VM:")
			for id := range runner.requests {
				fmt.Fprintf(buf, " %v", id)
			}
			fmt.Fprintf(buf, "\n\n")
			result := append(buf.Bytes(), msg.Data...)
			if infoc != nil {
				infoc <- result
				infoc = nil
			} else {
				// The request was solicited in detectTimeout().
				log.Logf(0, "status result: %s", result)
			}
		default:
			return fmt.Errorf("received unknown message type %T", msg)
		}
		if err != nil {
			return err
		}
	}
}

func wrappedRecv[Raw flatrpc.RecvType[T], T any](runner *Runner) (*T, error) {
	if runner.debugTimeouts {
		abort := runner.detectTimeout()
		defer close(abort)
	}
	return flatrpc.Recv[Raw](runner.conn)
}

func (runner *Runner) detectTimeout() chan struct{} {
	abort := make(chan struct{})
	go func() {
		select {
		case <-time.After(time.Minute):
			log.Logf(0, "timed out waiting for executor reply, aborting the connection in 1 minute")
			go func() {
				time.Sleep(time.Minute)
				runner.conn.Close()
			}()
			err := runner.sendStateRequest()
			if err != nil {
				log.Logf(0, "failed to send state request: %v", err)
				return
			}

		case <-abort:
			return
		case <-runner.finished:
			return
		}
	}()
	return abort
}

func (runner *Runner) sendStateRequest() error {
	msg := &flatrpc.HostMessage{
		Msg: &flatrpc.HostMessages{
			Type:  flatrpc.HostMessagesRawStateRequest,
			Value: &flatrpc.StateRequest{},
		},
	}
	return flatrpc.Send(runner.conn, msg)
}

func (runner *Runner) sendRequest(req *queue.Request) error {
	if err := req.Validate(); err != nil {
		panic(err)
	}
	runner.nextRequestID++
	id := runner.nextRequestID
	var flags flatrpc.RequestFlag
	if req.ReturnOutput {
		flags |= flatrpc.RequestFlagReturnOutput
	}
	if req.ReturnError {
		flags |= flatrpc.RequestFlagReturnError
	}
	allSignal := make([]int32, len(req.ReturnAllSignal))
	for i, call := range req.ReturnAllSignal {
		allSignal[i] = int32(call)
	}
	opts := req.ExecOpts
	if runner.debug {
		opts.EnvFlags |= flatrpc.ExecEnvDebug
	}
	var data []byte
	if req.BinaryFile == "" {
		progData, err := req.Prog.SerializeForExec()
		if err != nil {
			// It's bad if we systematically fail to serialize programs,
			// but so far we don't have a better handling than counting this.
			// This error is observed a lot on the seeded syz_mount_image calls.
			runner.stats.statExecBufferTooSmall.Add(1)
			req.Done(&queue.Result{Status: queue.ExecFailure})
			return nil
		}
		data = progData
	} else {
		flags |= flatrpc.RequestFlagIsBinary
		fileData, err := os.ReadFile(req.BinaryFile)
		if err != nil {
			req.Done(&queue.Result{
				Status: queue.ExecFailure,
				Err:    err,
			})
			return nil
		}
		data = fileData
	}
	var avoid uint64
	for _, id := range req.Avoid {
		if id.VM == runner.id {
			avoid |= uint64(1 << id.Proc)
		}
	}
	if avoid == (uint64(1)<<runner.procs)-1 {
		avoid = 0
	}
	msg := &flatrpc.HostMessage{
		Msg: &flatrpc.HostMessages{
			Type: flatrpc.HostMessagesRawExecRequest,
			Value: &flatrpc.ExecRequest{
				Id:        id,
				Avoid:     avoid,
				ProgData:  data,
				Flags:     flags,
				ExecOpts:  &opts,
				AllSignal: allSignal,
			},
		},
	}
	runner.requests[id] = req
	return flatrpc.Send(runner.conn, msg)
}

func (runner *Runner) handleExecutingMessage(msg *flatrpc.ExecutingMessage) error {
	req := runner.requests[msg.Id]
	if req == nil {
		return fmt.Errorf("can't find executing request %v", msg.Id)
	}
	proc := int(msg.ProcId)
	if proc < 0 || proc >= runner.procs {
		return fmt.Errorf("got bad proc id %v", proc)
	}
	runner.stats.statExecs.Add(1)
	if msg.Try == 0 {
		if msg.WaitDuration != 0 {
			runner.stats.statNoExecRequests.Add(1)
			// Cap wait duration to 1 second to avoid extreme peaks on the graph
			// which make it impossible to see real data (the rest becomes a flat line).
			runner.stats.statNoExecDuration.Add(int(min(msg.WaitDuration, 1e9)))
		}
	} else {
		runner.stats.statExecRetries.Add(1)
	}
	runner.lastExec.Note(int(msg.Id), proc, req.Prog.Serialize(), osutil.MonotonicNano())
	select {
	case runner.injectExec <- true:
	default:
	}
	runner.executing[msg.Id] = true
	return nil
}

func (runner *Runner) handleExecResult(msg *flatrpc.ExecResult) error {
	req := runner.requests[msg.Id]
	if req == nil {
		return fmt.Errorf("can't find executed request %v", msg.Id)
	}
	delete(runner.requests, msg.Id)
	delete(runner.executing, msg.Id)
	if msg.Info != nil {
		for len(msg.Info.Calls) < len(req.Prog.Calls) {
			msg.Info.Calls = append(msg.Info.Calls, &flatrpc.CallInfo{
				Error: 999,
			})
		}
		msg.Info.Calls = msg.Info.Calls[:len(req.Prog.Calls)]
		if msg.Info.Freshness == 0 {
			runner.stats.statExecutorRestarts.Add(1)
		}
		if !runner.cover && req.ExecOpts.ExecFlags&flatrpc.ExecFlagCollectSignal != 0 {
			// Coverage collection is disabled, but signal was requested => use a substitute signal.
			addFallbackSignal(req.Prog, msg.Info)
		}
		for _, call := range msg.Info.Calls {
			runner.convertCallInfo(call)
		}
		if len(msg.Info.ExtraRaw) != 0 {
			msg.Info.Extra = msg.Info.ExtraRaw[0]
			for _, info := range msg.Info.ExtraRaw[1:] {
				// All processing in the fuzzer later will convert signal/cover to maps and dedup,
				// so there is little point in deduping here.
				msg.Info.Extra.Cover = append(msg.Info.Extra.Cover, info.Cover...)
				msg.Info.Extra.Signal = append(msg.Info.Extra.Signal, info.Signal...)
			}
			msg.Info.ExtraRaw = nil
			runner.convertCallInfo(msg.Info.Extra)
		}
	}
	status := queue.Success
	var resErr error
	if msg.Error != "" {
		status = queue.ExecFailure
		resErr = errors.New(msg.Error)
	}
	req.Done(&queue.Result{
		Executor: queue.ExecutorID{
			VM:   runner.id,
			Proc: int(msg.Proc),
		},
		Status: status,
		Info:   msg.Info,
		Output: slices.Clone(msg.Output),
		Err:    resErr,
	})
	return nil
}

func (runner *Runner) convertCallInfo(call *flatrpc.CallInfo) {
	call.Cover = runner.canonicalizer.Canonicalize(call.Cover)
	call.Signal = runner.canonicalizer.Canonicalize(call.Signal)

	call.Comps = slices.DeleteFunc(call.Comps, func(cmp *flatrpc.Comparison) bool {
		converted := runner.canonicalizer.Canonicalize([]uint64{cmp.Pc})
		if len(converted) == 0 {
			return true
		}
		cmp.Pc = converted[0]
		return false
	})

	// Check signal belongs to kernel addresses.
	// Mismatching addresses can mean either corrupted VM memory, or that the fuzzer somehow
	// managed to inject output signal. If we see any bogus signal, drop whole signal
	// (we don't want programs that can inject bogus coverage to end up in the corpus).
	var kernelAddresses targets.KernelAddresses
	if runner.filterSignal {
		kernelAddresses = runner.sysTarget.KernelAddresses
	}
	textStart, textEnd := kernelAddresses.TextStart, kernelAddresses.TextEnd
	if textStart != 0 {
		for _, sig := range call.Signal {
			if sig < textStart || sig > textEnd {
				call.Signal = []uint64{}
				call.Cover = []uint64{}
				break
			}
		}
	}

	// Filter out kernel physical memory addresses.
	// These are internal kernel comparisons and should not be interesting.
	dataStart, dataEnd := kernelAddresses.DataStart, kernelAddresses.DataEnd
	if len(call.Comps) != 0 && (textStart != 0 || dataStart != 0) {
		if runner.sysTarget.PtrSize == 4 {
			// These will appear sign-extended in comparison operands.
			textStart = uint64(int64(int32(textStart)))
			textEnd = uint64(int64(int32(textEnd)))
			dataStart = uint64(int64(int32(dataStart)))
			dataEnd = uint64(int64(int32(dataEnd)))
		}
		isKptr := func(val uint64) bool {
			return val >= textStart && val <= textEnd || val >= dataStart && val <= dataEnd || val == 0
		}
		call.Comps = slices.DeleteFunc(call.Comps, func(cmp *flatrpc.Comparison) bool {
			return isKptr(cmp.Op1) && isKptr(cmp.Op2)
		})
	}
}

func (runner *Runner) SendSignalUpdate(plus []uint64) error {
	msg := &flatrpc.HostMessage{
		Msg: &flatrpc.HostMessages{
			Type: flatrpc.HostMessagesRawSignalUpdate,
			Value: &flatrpc.SignalUpdate{
				NewMax: runner.canonicalizer.Decanonicalize(plus),
			},
		},
	}
	return flatrpc.Send(runner.conn, msg)
}

func (runner *Runner) SendCorpusTriaged() error {
	msg := &flatrpc.HostMessage{
		Msg: &flatrpc.HostMessages{
			Type:  flatrpc.HostMessagesRawCorpusTriaged,
			Value: &flatrpc.CorpusTriaged{},
		},
	}
	return flatrpc.Send(runner.conn, msg)
}

func (runner *Runner) Stop() {
	runner.mu.Lock()
	runner.stopped = true
	conn := runner.conn
	runner.mu.Unlock()
	if conn != nil {
		conn.Close()
	}
}

func (runner *Runner) Shutdown(crashed bool) []ExecRecord {
	runner.mu.Lock()
	runner.stopped = true
	finished := runner.finished
	runner.mu.Unlock()

	if finished != nil {
		// Wait for the connection goroutine to finish and stop touching data.
		<-finished
	}
	for id, req := range runner.requests {
		status := queue.Restarted
		if crashed && runner.executing[id] {
			status = queue.Crashed
		}
		req.Done(&queue.Result{Status: status})
	}
	return runner.lastExec.Collect()
}

func (runner *Runner) MachineInfo() []byte {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	return runner.machineInfo
}

func (runner *Runner) QueryStatus() []byte {
	resc := make(chan []byte, 1)
	timeout := time.After(time.Minute)
	select {
	case runner.infoc <- resc:
	case <-timeout:
		return []byte("VM loop is not responding")
	}
	select {
	case res := <-resc:
		return res
	case <-timeout:
		return []byte("VM is not responding")
	}
}

func (runner *Runner) Alive() bool {
	runner.mu.Lock()
	defer runner.mu.Unlock()
	return runner.conn != nil && !runner.stopped
}

// addFallbackSignal computes simple fallback signal in cases we don't have real coverage signal.
// We use syscall number or-ed with returned errno value as signal.
// At least this gives us all combinations of syscall+errno.
func addFallbackSignal(p *prog.Prog, info *flatrpc.ProgInfo) {
	callInfos := make([]prog.CallInfo, len(info.Calls))
	for i, inf := range info.Calls {
		if inf.Flags&flatrpc.CallFlagExecuted != 0 {
			callInfos[i].Flags |= prog.CallExecuted
		}
		if inf.Flags&flatrpc.CallFlagFinished != 0 {
			callInfos[i].Flags |= prog.CallFinished
		}
		if inf.Flags&flatrpc.CallFlagBlocked != 0 {
			callInfos[i].Flags |= prog.CallBlocked
		}
		callInfos[i].Errno = int(inf.Error)
	}
	p.FallbackSignal(callInfos)
	for i, inf := range callInfos {
		info.Calls[i].Signal = inf.Signal
	}
}
