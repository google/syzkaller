// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package proxyapp

import (
	"net"
	"net/rpc"
	"net/rpc/jsonrpc"
	"net/url"
	"sync"
	"testing"

	"github.com/google/syzkaller/vm/proxyapp/proxyrpc"
	"github.com/google/syzkaller/vm/vmimpl"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func testTCPEnv(port string) *vmimpl.Env {
	return &vmimpl.Env{
		Config: []byte(`
{
		"rpc_server_uri": "localhost:` + port + `",
		"config": {
			"internal_values": 123
		}
	}
`)}
}

func proxyAppServerTCPFixture(t *testing.T) (*mockProxyAppInterface, string, *proxyAppParams) {
	mProxyAppServer, port, _ := makeMockProxyAppServer(t)
	return initProxyAppServerFixture(mProxyAppServer), port, makeTestParams()
}

func TestCtor_TCP_Ok(t *testing.T) {
	_, port, params := proxyAppServerTCPFixture(t)
	p, err := ctor(params, testTCPEnv(port))

	assert.Nil(t, err)
	assert.Equal(t, 2, p.Count())
}

func TestCtor_TCP_WrongPort(t *testing.T) {
	p, err := ctor(makeTestParams(), testTCPEnv("5"))

	assert.NotNil(t, err)
	assert.Nil(t, p)
}

func TestCtor_TCP_Reconnect_On_LostConnection(t *testing.T) {
	mProxyAppServer, port, closeServerConnections := makeMockProxyAppServer(t)
	onConnect := make(chan bool, 1)
	mProxyAppServer.
		On("CreatePool", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			out := args.Get(1).(*proxyrpc.CreatePoolResult)
			out.Count = 2
			onConnect <- true
		}).
		Return(nil).
		Times(2).
		On("PoolLogs", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			select {
			case mProxyAppServer.OnLogsReceived <- true:
			default:
			}
		}).
		Return(nil)

	ctor(makeTestParams(), testTCPEnv(port))
	<-onConnect
	<-mProxyAppServer.OnLogsReceived

	closeServerConnections()

	<-onConnect
	<-mProxyAppServer.OnLogsReceived
}

func TestCtor_TCP_Reconnect_PoolChanged(t *testing.T) {
	mProxyAppServer, port, closeServerConnections := makeMockProxyAppServer(t)
	onConnect := make(chan bool, 1)
	mProxyAppServer.
		On("CreatePool", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			out := args.Get(1).(*proxyrpc.CreatePoolResult)
			out.Count = 2
			onConnect <- true
		}).
		Return(nil).
		Once().
		On("CreatePool", mock.Anything, mock.Anything).
		Run(func(args mock.Arguments) {
			out := args.Get(1).(*proxyrpc.CreatePoolResult)
			out.Count = 1
			onConnect <- true
		}).
		Return(nil).
		On("PoolLogs", mock.Anything, mock.Anything).
		Return(nil)

	p, _ := ctor(makeTestParams(), testTCPEnv(port))
	<-onConnect
	closeServerConnections()
	for i := 0; i < 10; i++ {
		<-onConnect
		p.(*pool).mu.Lock()
		assert.Nil(t, p.(*pool).proxy) // still can't initialize
		p.(*pool).mu.Unlock()
	}
}

func makeMockProxyAppServer(t *testing.T) (*mockProxyAppInterface, string, func()) {
	handler := makeMockProxyAppInterface(t)
	server := rpc.NewServer()
	server.RegisterName("ProxyVM", struct{ proxyrpc.ProxyAppInterface }{handler})

	l, e := net.Listen("tcp", ":0")
	if e != nil {
		t.Fatalf("listen error: %v", e)
	}
	dest, err := url.Parse("http://" + l.Addr().String())
	if err != nil {
		t.Fatalf("failed to get server endpoint addr: %v", err)
	}

	connsMu := sync.Mutex{}
	var conns []net.Conn

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				panic("failed to accept connection")
			}
			go server.ServeCodec(jsonrpc.NewServerCodec(conn))

			connsMu.Lock()
			conns = append(conns, conn)
			connsMu.Unlock()
		}
	}()

	return handler, dest.Port(), func() {
		connsMu.Lock()
		defer connsMu.Unlock()
		for _, conn := range conns {
			conn.Close()
		}
	}
}
