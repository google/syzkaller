// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"compress/gzip"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/syzkaller/pkg/hubapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSyncHub(t *testing.T) {
	t.Run("noop when empty and not draining", func(t *testing.T) {
		calls := 0
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			calls++
		}))
		t.Cleanup(srv.Close)

		client, err := hubapi.NewClient("tool-client", srv.URL, "secret")
		require.NoError(t, err)
		require.NoError(t, syncHub(t.Context(), client, "mgr", nil, nil, false))
		assert.Equal(t, 0, calls)
	})

	t.Run("uploads corpus repros and drains", func(t *testing.T) {
		var gotConnect hubapi.ConnectReq
		var gotClient, gotManager string
		var syncReqs []hubapi.SyncReq
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			assert.Equal(t, "Bearer secret", r.Header.Get("Authorization"))
			switch r.URL.Path {
			case hubapi.PathConnect:
				gotClient = r.Header.Get(hubapi.HeaderClient)
				gotManager = r.Header.Get(hubapi.HeaderManager)
				gotConnect = decodeGzipBody[hubapi.ConnectReq](t, r)
				w.WriteHeader(http.StatusOK)
			case hubapi.PathSync:
				req := decodeGzipBody[hubapi.SyncReq](t, r)
				syncReqs = append(syncReqs, req)
				w.Header().Set("Content-Type", "application/json")
				var resp hubapi.SyncResp
				if len(syncReqs) == 2 {
					resp = hubapi.SyncResp{
						Inputs: []hubapi.Input{{Prog: []byte("getpid()\n")}},
						Repros: [][]byte{[]byte("repro\n")},
						More:   1,
					}
				}
				if err := json.NewEncoder(w).Encode(resp); err != nil {
					t.Error(err)
				}
			default:
				http.NotFound(w, r)
			}
		}))
		t.Cleanup(srv.Close)

		client, err := hubapi.NewClient("tool-client", srv.URL, "secret")
		require.NoError(t, err)
		corpus := [][]byte{[]byte("c1\n"), []byte("c2\n")}
		repros := [][]byte{[]byte("r1\n")}
		require.NoError(t, syncHub(t.Context(), client, "mgr-1", corpus, repros, true))

		assert.Equal(t, "tool-client", gotClient)
		assert.Equal(t, "mgr-1", gotManager)
		assert.Equal(t, corpus, gotConnect.Corpus)
		assert.False(t, gotConnect.Fresh)

		require.Len(t, syncReqs, 3)
		assert.Equal(t, repros, syncReqs[0].Repros)
		assert.False(t, syncReqs[0].NeedRepros)
		assert.True(t, syncReqs[1].NeedRepros)
		assert.Empty(t, syncReqs[1].Repros)
		assert.True(t, syncReqs[2].NeedRepros)
		assert.Empty(t, syncReqs[2].Repros)
	})
}

func decodeGzipBody[T any](t *testing.T, r *http.Request) T {
	t.Helper()
	var dst T
	gz, err := gzip.NewReader(r.Body)
	if err != nil {
		t.Error(err)
		return dst
	}
	defer gz.Close()
	if err := json.NewDecoder(gz).Decode(&dst); err != nil {
		t.Error(err)
	}
	return dst
}
