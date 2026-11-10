// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package rpctype

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

type testHub struct {
	connected atomic.Bool
}

func (h *testHub) CheckAuth(client, key, manager string) error {
	if client != "mgr" || key != "good-key" || !strings.HasPrefix(manager, client) {
		return fmt.Errorf("unauthorized manager")
	}
	return nil
}

func (h *testHub) Connect(a *HubConnectArgs, r *int) error {
	h.connected.Store(true)
	return nil
}

func (h *testHub) Sync(a *HubSyncArgs, r *HubSyncRes) error {
	r.Inputs = []HubInput{{Domain: "d", Prog: []byte("nop()")}}
	return nil
}

func newTestServer(t *testing.T) (*testHub, *RPCServer) {
	t.Helper()
	hub := &testHub{}
	srv, err := NewRPCServer("127.0.0.1:0", "Hub", hub)
	require.NoError(t, err)
	t.Cleanup(func() { _ = srv.Close() })
	go srv.Serve()
	return hub, srv
}

func TestRPCAuth(t *testing.T) {
	t.Run("bad_credentials", func(t *testing.T) {
		hub, srv := newTestServer(t)
		_, err := NewRPCClient(srv.Addr().String(), "attacker", "wrong-key", "attacker-mgr")
		require.ErrorContains(t, err, "unauthorized manager")
		require.False(t, hub.connected.Load())
	})

	t.Run("oversized_frame", func(t *testing.T) {
		hub, srv := newTestServer(t)
		conn, err := net.Dial("tcp", srv.Addr().String())
		require.NoError(t, err)
		defer conn.Close()

		_, err = conn.Write(binary.BigEndian.AppendUint32(nil, 10<<20))
		require.NoError(t, err)
		var res rpcAuthRes
		require.Error(t, readPreAuthMsg(conn, &res))
		require.False(t, hub.connected.Load())
	})

	t.Run("authenticated", func(t *testing.T) {
		hub, srv := newTestServer(t)
		cli, err := NewRPCClient(srv.Addr().String(), "mgr", "good-key", "mgr-0")
		require.NoError(t, err)
		defer cli.Close()

		args := &HubConnectArgs{
			Client:  "mgr",
			Key:     "good-key",
			Manager: "mgr-0",
			Corpus:  [][]byte{make([]byte, 256<<10)},
		}
		require.NoError(t, cli.Call("Hub.Connect", args, new(int)))
		require.True(t, hub.connected.Load())

		var r HubSyncRes
		require.NoError(t, cli.Call("Hub.Sync", &HubSyncArgs{
			Client:  "mgr",
			Key:     "good-key",
			Manager: "mgr-0",
		}, &r))
		require.Len(t, r.Inputs, 1)
	})
}
