// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package proxyapp package implements the experimental plugins support.
// We promise interface part will not be stable until documented.
package proxyapp

import (
	"context"
	"fmt"
	"io"
	"net/rpc"
	"net/rpc/jsonrpc"
	"os"
	"sync"
	"time"

	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/vm/proxyapp/proxyrpc"
	"github.com/google/syzkaller/vm/vmimpl"
)

func ctor(params *proxyAppParams, env *vmimpl.Env) (vmimpl.Pool, error) {
	subConfig, err := parseConfig(env.Config)
	if err != nil {
		return nil, fmt.Errorf("config parse error: %w", err)
	}

	p := &pool{
		env:      env,
		close:    make(chan bool, 1),
		onClosed: make(chan error, 1),
	}

	err = p.init(params, subConfig)
	if err != nil {
		return nil, fmt.Errorf("can't initialize pool: %w", err)
	}

	go func() {
		for {
			select {
			case <-p.close:
				p.mu.Lock()
				if p.proxy != nil {
					p.proxy.terminate()
					<-p.proxy.onTerminated
				}
				p.proxy = nil
				p.onClosed <- nil
				p.mu.Unlock()
				return
			case <-p.proxy.onTerminated:
			}
			p.mu.Lock()
			time.Sleep(params.InitRetryDelay)
			p.init(params, subConfig)
			p.mu.Unlock()
		}
	}()

	return p, nil
}

type pool struct {
	mu       sync.Mutex
	env      *vmimpl.Env
	proxy    *ProxyApp
	count    int
	close    chan bool
	onClosed chan error
}

func (p *pool) init(params *proxyAppParams, cfg *Config) error {
	var err error
	p.proxy, err = runProxyApp(params, cfg.Command)
	if err != nil {
		return fmt.Errorf("failed to run ProxyApp: %w", err)
	}

	count, err := p.proxy.CreatePool(string(cfg.ProxyAppConfig), p.env.Debug)
	if err != nil || count == 0 || (p.count != 0 && p.count != count) {
		if err == nil {
			err = fmt.Errorf("wrong pool size %v, prev was %v", count, p.count)
		}

		p.proxy.terminate()
		<-p.proxy.onTerminated
		p.proxy = nil

		return fmt.Errorf("failed to construct pool: %w", err)
	}

	if p.count == 0 {
		p.count = count
	}
	return nil
}

func (p *pool) Count() int {
	return p.count
}

func (p *pool) Create(workdir string, index int) (vmimpl.Instance, error) {
	p.mu.Lock()
	proxy := p.proxy
	p.mu.Unlock()

	if proxy == nil {
		return nil, fmt.Errorf("can't create instance using nil pool")
	}

	return proxy.CreateInstance(workdir, index)
}

// Close is not used now. Its support require wide code changes.
// TODO: support the pool cleanup on syz-manager level.
func (p *pool) Close() error {
	close(p.close)
	return <-p.onClosed
}

type ProxyApp struct {
	*rpc.Client
	terminate    context.CancelFunc
	onTerminated chan bool
}

func runProxyApp(params *proxyAppParams, cmd string) (*ProxyApp, error) {
	ctx, cancelContext := context.WithCancel(context.Background())
	subProcess := params.CommandRunner(ctx, cmd)
	var toClose []io.Closer
	freeAll := func() {
		for _, closer := range toClose {
			closer.Close()
		}
		cancelContext()
	}

	subStdout, err := subProcess.StdoutPipe()
	if err != nil {
		freeAll()
		return nil, fmt.Errorf("failed to get stdoutpipe: %w", err)
	}
	toClose = append(toClose, subStdout)

	subStdin, err := subProcess.StdinPipe()
	if err != nil {
		freeAll()
		return nil, fmt.Errorf("failed to get stdinpipe: %w", err)
	}
	toClose = append(toClose, subStdin)

	subprocessLogs, err := subProcess.StderrPipe()
	if err != nil {
		freeAll()
		return nil, fmt.Errorf("failed to get stderrpipe: %w", err)
	}
	toClose = append(toClose, subprocessLogs)

	codec := jsonrpc.NewClientCodec(stdInOutCloser{
		io.NopCloser(subStdout),
		subStdin,
	})

	if err := subProcess.Start(); err != nil {
		freeAll()
		return nil, fmt.Errorf("failed to start command %v: %w", cmd, err)
	}

	onTerminated := make(chan bool, 1)

	go func() {
		io.Copy(os.Stdout, subprocessLogs)
		if err := subProcess.Wait(); err != nil {
			log.Logf(0, "failed to Wait() subprocess: %v", err)
		}
		onTerminated <- true
	}()

	return &ProxyApp{
		Client:       rpc.NewClientWithCodec(codec),
		terminate:    cancelContext,
		onTerminated: onTerminated,
	}, nil
}

func (proxy *ProxyApp) CreatePool(config string, debug bool) (int, error) {
	var reply proxyrpc.CreatePoolResult
	err := proxy.Call(
		"ProxyVM.CreatePool",
		proxyrpc.CreatePoolParams{
			Debug: debug,
			Param: config,
		},
		&reply)
	if err != nil {
		return 0, err
	}

	return reply.Count, nil
}

func (proxy *ProxyApp) CreateInstance(workdir string, index int) (vmimpl.Instance, error) {
	var reply proxyrpc.CreateInstanceResult
	err := proxy.Call(
		"ProxyVM.CreateInstance",
		proxyrpc.CreateInstanceParams{
			Workdir: workdir,
			Index:   index},
		&reply)
	if err != nil {
		return nil, fmt.Errorf("failed to proxy.Call(\"ProxyVM.CreateInstance\"): %w", err)
	}

	return &instance{
		ProxyApp: proxy,
		ID:       reply.ID,
	}, nil
}

type instance struct {
	*ProxyApp
	ID string
}

// Copy copies a hostSrc file into VM and returns file name in VM.
// nolint: dupl
func (inst *instance) Copy(hostSrc string) (string, error) {
	var reply proxyrpc.CopyResult
	err := inst.ProxyApp.Call(
		"ProxyVM.Copy",
		proxyrpc.CopyParams{
			ID:      inst.ID,
			HostSrc: hostSrc,
		},
		&reply)
	if err != nil {
		return "", err
	}

	return reply.VMFileName, nil
}

// Forward sets up forwarding from within VM to the given tcp
// port on the host and returns the address to use in VM.
// nolint: dupl
func (inst *instance) Forward(port int) (string, error) {
	var reply proxyrpc.ForwardResult
	err := inst.ProxyApp.Call(
		"ProxyVM.Forward",
		proxyrpc.ForwardParams{
			ID:   inst.ID,
			Port: port,
		},
		&reply)
	if err != nil {
		return "", err
	}
	return reply.ManagerAddress, nil
}

func buildMerger(names ...string) (*vmimpl.OutputMerger, []io.Writer) {
	var wPipes []io.Writer
	merger := vmimpl.NewOutputMerger(nil)
	for _, name := range names {
		rpipe, wpipe := io.Pipe()
		wPipes = append(wPipes, wpipe)
		merger.Add(name, rpipe)
	}
	return merger, wPipes
}

func (inst *instance) Run(
	timeout time.Duration,
	stop <-chan bool,
	command string,
) (<-chan []byte, <-chan error, error) {
	merger, wPipes := buildMerger("stdout", "stderr", "console")
	receivedStdoutChunks := wPipes[0]
	receivedStderrChunks := wPipes[1]
	receivedConsoleChunks := wPipes[2]
	outc := merger.Output

	var reply proxyrpc.RunStartReply
	err := inst.ProxyApp.Call(
		"ProxyVM.RunStart",
		proxyrpc.RunStartParams{
			ID:      inst.ID,
			Command: command},
		&reply)

	if err != nil {
		return nil, nil, fmt.Errorf("error calling ProxyVM.Run with command %v: %w", command, err)
	}

	runID := reply.RunID
	terminationError := make(chan error, 1)
	timeoutSignal := time.After(timeout)
	signalClientErrorf := clientErrorf(receivedStderrChunks)

	go func() {
		for {
			var progress proxyrpc.RunReadProgressReply
			readProgressCall := inst.ProxyApp.Go(
				"ProxyVM.RunReadProgress",
				proxyrpc.RunReadProgressParams{
					ID:    inst.ID,
					RunID: runID,
				},
				&progress,
				nil)
			select {
			case <-readProgressCall.Done:
				receivedStdoutChunks.Write([]byte(progress.StdoutChunk))
				receivedStderrChunks.Write([]byte(progress.StderrChunk))
				receivedConsoleChunks.Write([]byte(progress.ConsoleOutChunk))
				if readProgressCall.Error != nil {
					signalClientErrorf("error reading progress from %v:%v: %v",
						inst.ID, runID, readProgressCall.Error)
				} else if progress.Error != "" {
					signalClientErrorf("%v", progress.Error)
				} else if progress.Finished {
					terminationError <- nil
				} else {
					continue
				}
			case <-timeoutSignal:
				// It is the happy path.
				inst.runStop(runID)
				terminationError <- vmimpl.ErrTimeout
			case <-stop:
				inst.runStop(runID)
				terminationError <- vmimpl.ErrTimeout
			}
			break
		}
	}()
	return outc, terminationError, nil
}

func (inst *instance) runStop(runID string) {
	err := inst.ProxyApp.Call(
		"ProxyVM.RunStop",
		proxyrpc.RunStopParams{
			ID:    inst.ID,
			RunID: runID,
		},
		&proxyrpc.RunStopParams{})
	if err != nil {
		log.Logf(0, "error calling runStop(%v) on %v: %v", runID, inst.ID, err)
	}
}

func (inst *instance) Diagnose(r *report.Report) (diagnosis []byte, wait bool) {
	var title string
	if r != nil {
		title = r.Title
	}
	var reply proxyrpc.DiagnoseReply
	err := inst.ProxyApp.Call(
		"ProxyVM.Diagnose",
		proxyrpc.DiagnoseParams{
			ID:          inst.ID,
			ReasonTitle: title,
		},
		&reply)
	if err != nil {
		return nil, false
	}

	return []byte(reply.Diagnosis), false
}

func (inst *instance) Close() {
	var reply proxyrpc.CloseReply
	err := inst.ProxyApp.Call(
		"ProxyVM.Close",
		proxyrpc.CloseParams{
			ID: inst.ID,
		},
		&reply)
	if err != nil {
		log.Logf(0, "error closing instance %v: %v", inst.ID, err)
	}
}

type stdInOutCloser struct {
	io.ReadCloser
	io.Writer
}

func clientErrorf(writer io.Writer) func(fmt string, s ...interface{}) {
	return func(f string, s ...interface{}) {
		writer.Write([]byte(fmt.Sprintf(f, s...)))
		writer.Write([]byte("\nSYZFAIL: proxy app plugin error\n"))
	}
}
