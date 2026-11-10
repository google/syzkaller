// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package rpctype

import (
	"crypto/rand"
	"fmt"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

type testHub struct {
	connected atomic.Bool
}

func (h *testHub) Connect(a *HubConnectArgs, r *int) error {
	h.connected.Store(true)
	return nil
}

func (h *testHub) Sync(a *HubSyncArgs, r *HubSyncRes) error {
	r.Inputs = []HubInput{{Domain: "d", Prog: []byte("nop()")}}
	return nil
}

func newTestRPC(t *testing.T) (*testHub, *RPCClient) {
	t.Helper()
	hub := &testHub{}
	srv, err := NewRPCServer("127.0.0.1:0", "Hub", hub)
	require.NoError(t, err)
	t.Cleanup(func() { _ = srv.Close() })
	go srv.Serve()

	cli, err := NewRPCClient(srv.Addr().String())
	require.NoError(t, err)
	t.Cleanup(cli.Close)
	return hub, cli
}

func TestFlateConnDecompressRatioLimit(t *testing.T) {
	t.Run("zero_bomb", func(t *testing.T) {
		hub, cli := newTestRPC(t)

		// A highly compressible payload (4 MiB of zeros) exceeds the 100:1 ratio
		// limit once more than minRatioCheckBytes (1 MiB) of excess output has been
		// decompressed, so gob decoding on the server aborts before Hub.Connect runs.
		args := &HubConnectArgs{
			Client:  "attacker",
			Key:     "wrong-key",
			Manager: "attacker-mgr",
			Corpus:  [][]byte{make([]byte, 4<<20)},
		}
		err := cli.Call("Hub.Connect", args, new(int))
		require.Error(t, err)
		require.False(t, hub.connected.Load(), "Hub.Connect should not be dispatched on decompression bomb")
	})

	t.Run("pre_credited_bomb", func(t *testing.T) {
		hub, cli := newTestRPC(t)

		// Verify that sending incompressible random data before a zero bomb in the
		// same RPC cannot bank unbounded credit to bypass the ratio limit.
		incompressible := make([]byte, 2<<20)
		_, err := rand.Read(incompressible)
		require.NoError(t, err)

		args := &HubConnectArgs{
			Client:  "attacker",
			Key:     "wrong-key",
			Manager: "attacker-mgr",
			Corpus:  [][]byte{incompressible, make([]byte, 4<<20)},
		}
		err = cli.Call("Hub.Connect", args, new(int))
		require.Error(t, err)
		require.False(t, hub.connected.Load(), "Hub.Connect should not be dispatched on pre-credited bomb")
	})
}

func TestFlateConnLegitimateTraffic(t *testing.T) {
	hub, cli := newTestRPC(t)

	const numProgs = 2000
	randBuf := make([]byte, numProgs*256)
	_, err := rand.Read(randBuf)
	require.NoError(t, err)

	corpus := make([][]byte, numProgs)
	for i := range corpus {
		p := make([]byte, 1024)
		copy(p[:256], randBuf[i*256:(i+1)*256])
		copy(p[256:], fmt.Sprintf("syz_open_dev$loop(&(0x7f0000000000)='%d', 0x0, 0x0)\n", i))
		corpus[i] = p
	}
	args := &HubConnectArgs{
		Client:  "mgr",
		Key:     "good-key",
		Manager: "mgr-0",
		Calls:   []string{"read", "write", "openat"},
		Corpus:  corpus,
	}
	require.NoError(t, cli.Call("Hub.Connect", args, new(int)))
	require.True(t, hub.connected.Load())

	for range 5 {
		var r HubSyncRes
		require.NoError(t, cli.Call("Hub.Sync", &HubSyncArgs{
			Client:  "mgr",
			Key:     "good-key",
			Manager: "mgr-0",
		}, &r))
		require.Len(t, r.Inputs, 1)
	}
}
