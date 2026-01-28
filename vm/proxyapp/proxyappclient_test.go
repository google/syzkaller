// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package proxyapp

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/rpc"
	"net/rpc/jsonrpc"
	"strings"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/vm/proxyapp/proxyrpc"
	"github.com/google/syzkaller/vm/vmimpl"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

var testEnv = &vmimpl.Env{
	Config: []byte(`
{
    "cmd": "/path/to/proxyapp_binary",
    "config": {
			"internal_values": 123
    }
  }
`)}

func makeTestParams() *proxyAppParams {
	return &proxyAppParams{
		CommandRunner:  osutilCommandContext,
		InitRetryDelay: 0,
		LogOutput:      io.Discard,
	}
}

func makeMockProxyAppProcess(t *testing.T) (
	*mockProxyAppInterface, io.WriteCloser, io.ReadCloser, io.ReadCloser) {
	rStdin, wStdin := io.Pipe()
	rStdout, wStdout := io.Pipe()
	rStderr, wStderr := io.Pipe()
	wStderr.Close()

	server := rpc.NewServer()
	handler := makeMockProxyAppInterface(t)
	server.RegisterName("ProxyVM", struct{ proxyrpc.ProxyAppInterface }{handler})

	go server.ServeCodec(jsonrpc.NewServerCodec(stdInOutCloser{
		rStdin,
		wStdout,
	}))

	return handler, wStdin, rStdout, rStderr
}

type nopWriteCloser struct {
	io.Writer
}

func (nopWriteCloser) Close() error {
	return nil
}

func TestCtor_Ok(t *testing.T) {
	_, mCmdRunner, params := proxyAppServerFixture(t)
	p, err := ctor(params, testEnv)

	assert.Nil(t, err)
	assert.Equal(t, 2, p.Count())

	<-mCmdRunner.onWaitCalled
}

func TestCtor_ReadBadConfig(t *testing.T) {
	pool, err := ctor(makeTestParams(), &vmimpl.Env{
		Config: []byte(`{"wrong_key": 1}`),
	})
	assert.NotNil(t, err)
	assert.Nil(t, pool)
}

func TestCtor_FailedPipes(t *testing.T) {
	mCmdRunner, params := makeMockCommandRunner(t)
	mCmdRunner.
		On("StdinPipe").
		Return(nil, fmt.Errorf("stdinpipe error")).
		Once().
		On("StdinPipe").
		Return(nopWriteCloser{&bytes.Buffer{}}, nil).
		On("StdoutPipe").
		Return(nil, fmt.Errorf("stdoutpipe error")).
		Once().
		On("StdoutPipe").
		Return(io.NopCloser(strings.NewReader("")), nil).
		On("StderrPipe").
		Return(nil, fmt.Errorf("stderrpipe error")).
		Once().
		On("StderrPipe").
		Return(io.NopCloser(strings.NewReader("")), nil)

	for i := 0; i < 3; i++ {
		p, err := ctor(params, testEnv)
		assert.NotNil(t, err)
		assert.Nil(t, p)
	}
}

func TestClose_waitDone(t *testing.T) {
	_, mCmdRunner, params := proxyAppServerFixture(t)
	mCmdRunner.
		On("waitDone").
		Return(nil)

	p, _ := ctor(params, testEnv)
	p.(io.Closer).Close()
}

func TestCtor_FailedStartProxyApp(t *testing.T) {
	mCmdRunner, params := makeMockCommandRunner(t)
	mCmdRunner.
		On("StdinPipe").
		Return(nopWriteCloser{&bytes.Buffer{}}, nil).
		On("StdoutPipe").
		Return(io.NopCloser(strings.NewReader("")), nil).
		On("StderrPipe").
		Return(io.NopCloser(strings.NewReader("")), nil).
		On("Start").
		Return(fmt.Errorf("failed to start program"))

	p, err := ctor(params, testEnv)
	assert.NotNil(t, err)
	assert.Nil(t, p)
}

// TODO: reuse proxyAppServerFixture() code: func could be called here once Mock.Unset() error.
func TestCtor_FailedConstructPool(t *testing.T) {
	mProxyAppServer, stdin, stdout, stderr :=
		makeMockProxyAppProcess(t)

	mProxyAppServer.
		On("CreatePool", mock.Anything, mock.Anything).
		Return(fmt.Errorf("failed to construct pool")).
		On("PoolLogs", mock.Anything, mock.Anything).
		Return(nil).
		Maybe() // on CreatePool error we close logger. This close makes PoolLogs racy.

	mCmdRunner, params := makeMockCommandRunner(t)
	mCmdRunner.
		On("StdinPipe").
		Return(stdin, nil).
		On("StdoutPipe").
		Return(stdout, nil).
		On("StderrPipe").
		Return(stderr, nil).
		On("Start").
		Return(nil).
		On("Wait").
		Run(func(args mock.Arguments) {
			<-mCmdRunner.ctx.Done()
		}).
		Return(nil)

	p, err := ctor(params, testEnv)
	assert.NotNil(t, err)
	assert.Nil(t, p)
}

func initProxyAppServerFixture(mProxyAppServer *mockProxyAppInterface) *mockProxyAppInterface {
	mProxyAppServer.
		On("CreatePool", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			out := args.Get(1).(*proxyrpc.CreatePoolResult)
			out.Count = 2
		}).
		Return(nil).
		Once().
		On("PoolLogs", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			select {
			case mProxyAppServer.OnLogsReceived <- true:
			default:
			}
		}).
		Return(nil).
		// PoolLogs is optional as we can call .closeProxy any time.
		// If PoolLogs call is expected we are checking for OnLogsReceived.
		// TODO: refactor it once Mock.Unset() is available.
		Maybe()

	return mProxyAppServer
}

// TODO: to remove duplicate see TestCtor_FailedConstructPool() comment.
func proxyAppServerFixture(t *testing.T) (*mockProxyAppInterface, *mockCommandRunner, *proxyAppParams) {
	mProxyAppServer, stdin, stdout, stderr :=
		makeMockProxyAppProcess(t)
	initProxyAppServerFixture(mProxyAppServer)

	mCmdRunner, params := makeMockCommandRunner(t)
	mCmdRunner.
		On("StdinPipe").
		Return(stdin, nil).
		On("StdoutPipe").
		Return(stdout, nil).
		On("StderrPipe").
		Return(stderr, nil).
		On("Start").
		Return(nil).
		On("Wait").
		Run(func(args mock.Arguments) {
			<-mCmdRunner.ctx.Done()
			mCmdRunner.MethodCalled("waitDone")
		}).
		Return(nil).
		Maybe()

	return mProxyAppServer, mCmdRunner, params
}

func poolFixture(t *testing.T) (*mockProxyAppInterface, *mockCommandRunner, vmimpl.Pool) {
	mProxyAppServer, mCmdRunner, params := proxyAppServerFixture(t)
	p, _ := ctor(params, testEnv)
	return mProxyAppServer, mCmdRunner, p
}

func TestPool_Create_Ok(t *testing.T) {
	mockServer, _, p := poolFixture(t)
	mockServer.
		On("CreateInstance", mock.Anything, mock.Anything).
		Return(nil)

	inst, err := p.Create(t.Context(), "workdir", 0)
	assert.NotNil(t, inst)
	assert.Nil(t, err)
}

func TestPool_Logs_Ok(t *testing.T) {
	mockServer, _, _ := poolFixture(t)
	<-mockServer.OnLogsReceived
}

func TestPool_Create_ProxyNilError(t *testing.T) {
	_, mCmdRunner, p := poolFixture(t)
	mCmdRunner.
		On("waitDone").
		Return(nil)

	p.(io.Closer).Close()

	inst, err := p.Create(t.Context(), "workdir", 0)
	assert.Nil(t, inst)
	assert.NotNil(t, err)
}

func TestPool_Create_OutOfPoolError(t *testing.T) {
	mockServer, _, p := poolFixture(t)
	mockServer.
		On("CreateInstance", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			in := args.Get(0).(proxyrpc.CreateInstanceParams)
			assert.Equal(t, p.Count(), in.Index)
		}).
		Return(fmt.Errorf("out of pool size"))

	inst, err := p.Create(t.Context(), "workdir", p.Count())
	assert.Nil(t, inst)
	assert.NotNil(t, err)
}

func TestPool_Create_ProxyFailure(t *testing.T) {
	mockServer, _, p := poolFixture(t)
	mockServer.
		On("CreateInstance", mock.Anything, mock.Anything).
		Return(fmt.Errorf("create instance failure"))

	inst, err := p.Create(t.Context(), "workdir", 0)
	assert.Nil(t, inst)
	assert.NotNil(t, err)
}

// nolint: dupl
func createInstanceFixture(t *testing.T) (*mock.Mock, vmimpl.Instance) {
	mockServer, _, p := poolFixture(t)
	mockServer.
		On("CreateInstance", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			in := args.Get(0).(proxyrpc.CreateInstanceParams)
			out := args.Get(1).(*proxyrpc.CreateInstanceResult)
			out.ID = fmt.Sprintf("instance_id_%v", in.Index)
		}).
		Return(nil)

	inst, err := p.Create(t.Context(), "workdir", 0)
	assert.Nil(t, err)
	assert.NotNil(t, inst)

	return &mockServer.Mock, inst
}

func TestInstance_Close(t *testing.T) {
	mockInstance, inst := createInstanceFixture(t)
	mockInstance.
		On("Close", mock.Anything, mock.Anything).
		Return(fmt.Errorf("mock error"))

	inst.Close()
}

func TestInstance_Diagnose_Ok(t *testing.T) {
	mockInstance, inst := createInstanceFixture(t)
	mockInstance.
		On("Diagnose", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			out := args.Get(1).(*proxyrpc.DiagnoseReply)
			out.Diagnosis = "diagnostic result"
		}).
		Return(nil)

	diagnosis, wait := inst.Diagnose(nil)
	assert.NotNil(t, diagnosis)
	assert.Equal(t, wait, false)

	diagnosis, wait = inst.Diagnose(&report.Report{})
	assert.NotNil(t, diagnosis)
	assert.Equal(t, wait, false)
}

func TestInstance_Diagnose_Failure(t *testing.T) {
	mockInstance, inst := createInstanceFixture(t)
	mockInstance.
		On("Diagnose", mock.Anything, mock.Anything).
		Return(fmt.Errorf("diagnose failed"))

	diagnosis, wait := inst.Diagnose(&report.Report{})
	assert.Nil(t, diagnosis)
	assert.Equal(t, wait, false)
}

func TestInstance_Copy_OK(t *testing.T) {
	mockInstance, inst := createInstanceFixture(t)
	mockInstance.
		On("Copy", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			out := args.Get(1).(*proxyrpc.CopyResult)
			out.VMFileName = "remote_file_path"
		}).
		Return(nil)

	remotePath, err := inst.Copy("host/path")
	assert.Nil(t, err)
	assert.NotEmpty(t, remotePath)
}

func TestInstance_Copy_Failure(t *testing.T) {
	mockInstance, inst := createInstanceFixture(t)
	mockInstance.
		On("Copy", mock.Anything, mock.Anything).
		Return(fmt.Errorf("copy failure"))

	remotePath, err := inst.Copy("host/path")
	assert.NotNil(t, err)
	assert.Empty(t, remotePath)
}

// nolint: dupl
func TestInstance_Forward_OK(t *testing.T) {
	mockInstance, inst := createInstanceFixture(t)
	mockInstance.
		On("Forward", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			in := args.Get(0).(proxyrpc.ForwardParams)
			out := args.Get(1).(*proxyrpc.ForwardResult)
			out.ManagerAddress = fmt.Sprintf("manager_address:%v", in.Port)
		}).
		Return(nil)

	remoteAddressToUse, err := inst.Forward(12345)
	assert.Nil(t, err)
	assert.Equal(t, "manager_address:12345", remoteAddressToUse)
}

func TestInstance_Forward_Failure(t *testing.T) {
	mockInstance, inst := createInstanceFixture(t)
	mockInstance.
		On("Forward", mock.Anything, mock.Anything).
		Return(fmt.Errorf("forward failure"))

	remoteAddressToUse, err := inst.Forward(12345)
	assert.NotNil(t, err)
	assert.Empty(t, remoteAddressToUse)
}

func TestInstance_Run_Failure(t *testing.T) {
	mockInstance, inst := createInstanceFixture(t)
	mockInstance.
		On("RunStart", mock.Anything, mock.Anything).
		Return(fmt.Errorf("run start error"))

	outc, errc, err := inst.Run(contextWithTimeout(t, 10*time.Second), "command")
	assert.Nil(t, outc)
	assert.Nil(t, errc)
	assert.NotEmpty(t, err)
}

func TestInstance_Run_OnTimeout(t *testing.T) {
	mockInstance, inst := createInstanceFixture(t)
	mockInstance.
		On("RunStart", mock.Anything, mock.Anything).
		Return(nil).
		On("RunReadProgress", mock.Anything, mock.Anything).
		Return(nil).Maybe().
		On("RunStop", mock.Anything, mock.Anything).
		Return(nil)

	_, errc, _ := inst.Run(contextWithTimeout(t, time.Second), "command")
	err := <-errc

	assert.Equal(t, err, vmimpl.ErrTimeout)
}

func TestInstance_Run_OnStop(t *testing.T) {
	mockInstance, inst := createInstanceFixture(t)
	mockInstance.
		On("RunStart", mock.Anything, mock.Anything).
		Return(nil).
		On("RunReadProgress", mock.Anything, mock.Anything).
		Return(nil).
		Maybe().
		On("RunStop", mock.Anything, mock.Anything).
		Return(nil)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	_, errc, _ := inst.Run(ctx, "command")
	cancel()
	err := <-errc
	assert.Equal(t, err, vmimpl.ErrTimeout)
}

func TestInstance_RunReadProgress_OnErrorReceived(t *testing.T) {
	mockInstance, inst := createInstanceFixture(t)
	mockInstance.
		On("RunStart", mock.Anything, mock.Anything).
		Return(nil).
		On("RunReadProgress", mock.Anything, mock.Anything).
		Return(nil).
		Times(100).
		On("RunReadProgress", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			out := args.Get(1).(*proxyrpc.RunReadProgressReply)
			out.Error = "mock error"
		}).
		Return(nil).
		Once()

	outc, _, _ := inst.Run(contextWithTimeout(t, 10*time.Second), "command")
	output := string((<-outc).Data)

	assert.Equal(t, "mock error\nSYZFAIL: proxy app plugin error\n", output)
}

func TestInstance_RunReadProgress_OnFinished(t *testing.T) {
	mockInstance, inst := createInstanceFixture(t)
	mockInstance.
		On("RunStart", mock.Anything, mock.Anything).
		Return(nil).
		On("RunReadProgress", mock.Anything, mock.Anything).
		Return(nil).Times(100).
		On("RunReadProgress", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			out := args.Get(1).(*proxyrpc.RunReadProgressReply)
			out.Finished = true
		}).
		Return(nil).
		Once()

	_, errc, _ := inst.Run(contextWithTimeout(t, 10*time.Second), "command")
	err := <-errc

	assert.Equal(t, err, nil)
}

func TestInstance_RunReadProgress_Failed(t *testing.T) {
	mockInstance, inst := createInstanceFixture(t)
	mockInstance.
		On("RunStart", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			out := args.Get(1).(*proxyrpc.RunStartReply)
			out.RunID = "test_run_id"
		}).
		Return(nil).
		On("RunReadProgress", mock.Anything, mock.Anything).
		Return(fmt.Errorf("runreadprogresserror")).
		Once()

	outc, _, _ := inst.Run(contextWithTimeout(t, 10*time.Second), "command")
	output := string((<-outc).Data)

	assert.Equal(t,
		"error reading progress from instance_id_0:test_run_id: runreadprogresserror\nSYZFAIL: proxy app plugin error\n",
		output,
	)
}

// TODO: test for periodical proxyapp subprocess crashes handling.
//  [option] check pool size was changed

// TODO: test pool.Close() calls plugin API and return error.

func contextWithTimeout(t *testing.T, timeout time.Duration) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	t.Cleanup(cancel)
	return ctx
}
