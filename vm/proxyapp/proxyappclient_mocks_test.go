// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package proxyapp

//go:generate ../../tools/mockery.sh --name subProcessCmd --exported
//go:generate ../../tools/mockery.sh --name ProxyAppInterface -r

import (
	"context"
	"testing"

	"github.com/google/syzkaller/vm/proxyapp/mocks"
	"github.com/google/syzkaller/vm/proxyapp/proxyrpc"
)

var (
	_ subProcessCmd              = &mocks.SubProcessCmd{}
	_ proxyrpc.ProxyAppInterface = &mocks.ProxyAppInterface{}
)

type mockCommandRunner struct {
	*mocks.SubProcessCmd
	ctx          context.Context
	onWaitCalled chan bool
}

func makeMockCommandRunner(t *testing.T) (*mockCommandRunner, *proxyAppParams) {
	cmdRunner := &mockCommandRunner{
		SubProcessCmd: mocks.NewSubProcessCmd(t),
		onWaitCalled:  make(chan bool, 1),
	}

	params := makeTestParams()
	params.CommandRunner = func(ctx context.Context, cmd string, params ...string) subProcessCmd {
		cmdRunner.ctx = ctx
		return cmdRunner
	}
	return cmdRunner, params
}

func (cmd *mockCommandRunner) Wait() error {
	cmd.onWaitCalled <- true
	return cmd.SubProcessCmd.Wait()
}

type mockProxyAppInterface struct {
	*mocks.ProxyAppInterface
	OnLogsReceived chan bool
}

func makeMockProxyAppInterface(t mocks.NewProxyAppInterfaceT) *mockProxyAppInterface {
	return &mockProxyAppInterface{
		ProxyAppInterface: mocks.NewProxyAppInterface(t),
		OnLogsReceived:    make(chan bool, 1), // 1 is enough as we read it just once
	}
}
