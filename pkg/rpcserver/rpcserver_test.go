// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package rpcserver

import (
	"context"
	"net"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/rpcserver/mocks"
	"github.com/google/syzkaller/pkg/vminfo"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
	"golang.org/x/sync/errgroup"
)

func getTestDefaultCfg() mgrconfig.Config {
	return mgrconfig.Config{
		Type:    targets.Linux,
		Sandbox: "none",
		Derived: mgrconfig.Derived{
			TargetOS:     targets.TestOS,
			TargetArch:   targets.TestArch64,
			TargetVMArch: targets.TestArch64,
			Timeouts:     targets.Timeouts{Slowdown: 1},
		},
	}
}

func TestNew(t *testing.T) {
	defaultCfg := getTestDefaultCfg()

	nilServer := func(s Server) {
		assert.Nil(t, s)
	}

	tests := []struct {
		name              string
		modifyCfg         func() *mgrconfig.Config
		debug             bool
		expectedServCheck func(Server)
		expectsErr        bool
		expectedErr       error
	}{
		{
			name: "unknown Sandbox",
			modifyCfg: func() *mgrconfig.Config {
				cfg := defaultCfg
				cfg.Sandbox = "unknown"
				return &cfg
			},
			expectedServCheck: nilServer,
			expectsErr:        true,
		},
		{
			name: "experimental features",
			modifyCfg: func() *mgrconfig.Config {
				cfg := defaultCfg
				cfg.Experimental = mgrconfig.Experimental{
					RemoteCover: false,
					CoverEdges:  true,
				}
				return &cfg
			},
			expectedServCheck: func(srv Server) {
				s := srv.(*server)
				assert.Equal(t, s.cfg.Config.Features,
					flatrpc.AllFeatures&(^flatrpc.FeatureExtraCoverage)&(^flatrpc.FeatureMemoryDump))
				assert.Nil(t, s.serv)
			},
		},
		{
			name: "memory dump enabled",
			modifyCfg: func() *mgrconfig.Config {
				cfg := defaultCfg
				cfg.MemoryDump = true
				return &cfg
			},
			expectedServCheck: func(srv Server) {
				s := srv.(*server)
				assert.Equal(t, s.cfg.Config.Features, flatrpc.AllFeatures&(^flatrpc.FeatureExtraCoverage))
				assert.Nil(t, s.serv)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := tt.modifyCfg()

			var err error
			cfg.Target, err = prog.GetTarget(cfg.TargetOS, cfg.TargetArch)
			assert.NoError(t, err)

			serv, err := New(&RemoteConfig{
				Config: cfg,
				Stats:  NewStats(),
				Debug:  tt.debug,
			})
			if tt.expectedErr != nil {
				assert.Equal(t, tt.expectedErr, err)
			} else if tt.expectsErr {
				assert.Error(t, err)
			} else {
				assert.Nil(t, err)
			}
			tt.expectedServCheck(serv)
		})
	}
}

func TestCheckRevisions(t *testing.T) {
	tests := []struct {
		name    string
		req     *flatrpc.ConnectRequest
		target  *prog.Target
		noError bool
	}{
		{
			name: "error - different Arch",
			req: &flatrpc.ConnectRequest{
				Arch: "arch",
			},
			target: &prog.Target{
				Arch: "arch2",
			},
		},
		{
			name: "error - different GitRevision",
			req: &flatrpc.ConnectRequest{
				Arch:        "arch",
				GitRevision: "different",
			},
			target: &prog.Target{
				Arch: "arch",
			},
		},
		{
			name: "error - different SyzRevision",
			req: &flatrpc.ConnectRequest{
				Arch:        "arch",
				GitRevision: prog.GitRevision,
				SyzRevision: "1",
			},
			target: &prog.Target{
				Arch:     "arch",
				Revision: "2",
			},
		},
		{
			name: "ok",
			req: &flatrpc.ConnectRequest{
				Arch:        "arch",
				GitRevision: prog.GitRevision,
				SyzRevision: "1",
			},
			target: &prog.Target{
				Arch:     "arch",
				Revision: "1",
			},
			noError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkRevisions(tt.req, tt.target)
			if tt.noError {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestHandleConn(t *testing.T) {
	inConn, outConn := net.Pipe()
	serverConn := flatrpc.NewConn(inConn)
	clientConn := flatrpc.NewConn(outConn)

	managerMock := mocks.NewManager(t)
	debug := false
	defaultCfg := getTestDefaultCfg()

	tests := []struct {
		name       string
		wantErrMsg string
		modifyCfg  func() *mgrconfig.Config
		req        *flatrpc.ConnectRequest
	}{
		{
			name:       "error, cfg.VMLess = false - unknown VM tries to connect",
			wantErrMsg: "tries to connect",
			modifyCfg: func() *mgrconfig.Config {
				return &defaultCfg
			},
			req: &flatrpc.ConnectRequest{
				Id:          2, // Valid Runner id is 1.
				Arch:        "64",
				GitRevision: prog.GitRevision,
				SyzRevision: "1",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := tt.modifyCfg()

			var err error
			cfg.Target, err = prog.GetTarget(cfg.TargetOS, cfg.TargetArch)
			cfg.Target.Revision = tt.req.SyzRevision
			assert.NoError(t, err)

			s, err := New(&RemoteConfig{
				Config:  cfg,
				Manager: managerMock,
				Stats:   NewStats(),
				Debug:   debug,
			})
			assert.NoError(t, err)
			serv := s.(*server)

			injectExec := make(chan bool)
			serv.CreateInstance(1, injectExec, nil)
			g := errgroup.Group{}
			g.Go(func() error {
				hello, err := flatrpc.Recv[*flatrpc.ConnectHelloRaw](clientConn)
				if err != nil {
					return err
				}
				tt.req.Cookie = authHash(hello.Cookie)
				flatrpc.Send(clientConn, tt.req)
				return nil
			})
			if err := serv.handleConn(context.Background(), serverConn); err != nil {
				if !strings.Contains(err.Error(), tt.wantErrMsg) {
					t.Fatal(err)
				}
			}
			if err := g.Wait(); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestMachineCheckCrash(t *testing.T) {
	target, err := prog.GetTarget(targets.TestOS, targets.TestArch64Fuzz)
	if err != nil {
		t.Fatal(err)
	}
	sysTarget := targets.Get(target.OS, target.Arch)
	if sysTarget.BrokenCompiler != "" {
		t.Skipf("skipping, broken cross-compiler: %v", sysTarget.BrokenCompiler)
	}
	executor := csource.BuildExecutor(t, target, "../..")

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	checkBegan := make(chan struct{})
	cfg := &LocalConfig{
		Config: Config{
			Config: vminfo.Config{
				Target:   target,
				Features: flatrpc.FeatureSandboxNone,
				Sandbox:  flatrpc.ExecEnvSandboxNone,
			},
			Procs:               4,
			Slowdown:            1,
			machineCheckStarted: checkBegan,
		},
		Executor: executor,
		Dir:      t.TempDir(),
	}
	cfg.MachineChecked = func(features flatrpc.Feature, syscalls map[*prog.Syscall]bool) queue.Source {
		cancel()
		return queue.Callback(func() *queue.Request {
			return nil
		})
	}

	local, ctx, err := setupLocal(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	loopDone := make(chan error)
	go func() {
		loopDone <- local.Serve(ctx)
	}()

	t.Logf("starting the first instance")
	firstCtx, firstCancel := context.WithCancel(ctx)
	firstCh := make(chan error)
	go func() {
		firstCh <- local.RunInstance(firstCtx, 0)
	}()

	t.Logf("wait for the machine check to begin")
	<-checkBegan

	t.Logf("kill the first instance")
	firstCancel()
	if err := <-firstCh; err != nil {
		t.Fatal(err)
	}

	t.Logf("restart the instance")
	secondCh := make(chan error)
	go func() {
		secondCh <- local.RunInstance(ctx, 0)
	}()

	t.Logf("await the completion")
	if err := <-loopDone; err != nil {
		t.Fatal(err)
	}
	if err := <-secondCh; err != nil {
		t.Fatal(err)
	}
}
