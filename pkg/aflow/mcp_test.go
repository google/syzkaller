// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMCPToolReply(t *testing.T) {
	// On a badCallError the structured result is dropped and only the error is
	// reported, matching the native agentSession.callTools path. A boxed nil map
	// would otherwise marshal as "structuredContent": null, which strict clients
	// reject, discarding the error text with it.
	t.Run("nil result on bad call", func(t *testing.T) {
		reply, err := mcpToolReply(nil, BadCallError("missing argument %q", "KernelCommit"))
		require.NoError(t, err)
		data := marshal(t, reply)
		assert.NotContains(t, data, `"structuredContent"`, "nil result must omit structuredContent, got: %s", data)
		assert.Contains(t, data, `"isError":true`, "the error must still be reported, got: %s", data)
		assert.Contains(t, data, `missing argument \"KernelCommit\"`, "the error text must reach the client, got: %s", data)
	})

	// funcTool.execute returns convertToMap(zeroResults), a non-nil map, when the
	// tool Func itself returns a badCallError. That zero-valued object must not be
	// sent either; only the error should reach the client.
	t.Run("non-nil result on bad call", func(t *testing.T) {
		reply, err := mcpToolReply(map[string]any{"Verdict": "", "Count": 0}, BadCallError("reasoning must be provided"))
		require.NoError(t, err)
		data := marshal(t, reply)
		assert.NotContains(t, data, `"structuredContent"`, "a result alongside an error must be dropped, got: %s", data)
		assert.Contains(t, data, `"isError":true`, "the error must still be reported, got: %s", data)
		assert.Contains(t, data, `reasoning must be provided`, "the error text must reach the client, got: %s", data)
	})

	// A successful call keeps its structured result.
	t.Run("result on success", func(t *testing.T) {
		reply, err := mcpToolReply(map[string]any{"ok": true}, nil)
		require.NoError(t, err)
		data := marshal(t, reply)
		assert.Contains(t, data, `"structuredContent"`, "a successful result must keep structuredContent, got: %s", data)
	})

	// An empty (but non-nil) result from a struct{} Results is still sent, as {}.
	t.Run("empty result on success", func(t *testing.T) {
		reply, err := mcpToolReply(map[string]any{}, nil)
		require.NoError(t, err)
		data := marshal(t, reply)
		assert.Contains(t, data, `"structuredContent":{}`, "an empty success result must be sent as {}, got: %s", data)
	})

	// A non-badCallError is returned to the caller unchanged, with no reply.
	t.Run("fatal error is propagated", func(t *testing.T) {
		reply, err := mcpToolReply(nil, errors.New("fatal"))
		require.Error(t, err)
		assert.Nil(t, reply)
	})
}

func marshal(t *testing.T, v any) string {
	t.Helper()
	data, err := json.Marshal(v)
	require.NoError(t, err)
	return string(data)
}
