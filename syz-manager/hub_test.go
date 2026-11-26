// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"compress/gzip"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/google/syzkaller/pkg/corpus"
	"github.com/google/syzkaller/pkg/fuzzer"
	"github.com/google/syzkaller/pkg/hubapi"
	"github.com/google/syzkaller/pkg/manager"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/stat"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMatchDomains(t *testing.T) {
	type Test struct {
		self      string
		input     string
		minimized bool
		smashed   bool
	}
	tests := []Test{
		{"", "", true, true},
		{"linux", "", true, true},
		{"linux/", "", true, true},
		{"linux/upstream/kasan", "", true, true},
		{"", "linux", true, true},
		{"", "linux/", true, true},
		{"linux", "linux/", false, false},
		{"linux/", "linux/", false, false},
		{"linux", "linuz", true, true},
		{"linux/upstream/kasan", "linuz", true, true},
		{"linux/upstream", "linux/upstream", false, false},
		{"linux/upstream", "linux/upstreax", true, true},
		{"linux/upstream/", "linux/upstream", false, false},
		{"linux/upstream", "linux/upstreax/", true, true},
		{"linux/upstream", "linux/upstream/kasan", false, true},
		{"linux/upstream/kasan", "linux/upstream", false, true},
		{"linux/upstream/kasan", "linux/upstream/xasan", false, true},
		{"linux/upstream/kasan", "linux/upstream/kasan", false, false},
		{"linux/upstreax/kasan", "linux/upstream/kasan", true, true},
		{"linux/upstreax/kasan", "linux/upstream/xasan", true, true},
		{"linux/upstream/kasan", "linuz/upstream/xasan", true, true},
	}
	for i, test := range tests {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			minimized, smashed := matchDomains(test.self, test.input)
			if minimized != test.minimized || smashed != test.smashed {
				t.Fatalf("(%q, %q) = %v/%v, want %v/%v",
					test.self, test.input, minimized, smashed, test.minimized, test.smashed)
			}
		})
	}
}

func TestHubConnectorHTTP(t *testing.T) {
	target, err := prog.GetTarget(targets.TestOS, targets.TestArch64)
	require.NoError(t, err)
	var call *prog.Syscall
	for _, c := range target.Syscalls {
		if !c.Attrs.Disabled {
			call = c
			break
		}
	}
	require.NotNil(t, call)
	p, err := target.Deserialize([]byte(call.Name+"()\n"), prog.NonStrict)
	require.NoError(t, err)
	raw := p.Serialize()

	var failNext bool
	var gotConnect hubapi.ConnectReq
	var gotClient, gotManager string
	var syncReqs []hubapi.SyncReq
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "Bearer test-secret", r.Header.Get("Authorization"))
		if failNext {
			failNext = false
			http.Error(w, "unconnected manager", http.StatusConflict)
			return
		}
		gz, err := gzip.NewReader(r.Body)
		if err != nil {
			t.Error(err)
			return
		}
		defer gz.Close()

		switch r.URL.Path {
		case hubapi.PathConnect:
			gotClient = r.Header.Get(hubapi.HeaderClient)
			gotManager = r.Header.Get(hubapi.HeaderManager)
			if err := json.NewDecoder(gz).Decode(&gotConnect); err != nil {
				t.Error(err)
				return
			}
			w.WriteHeader(http.StatusOK)
		case hubapi.PathSync:
			var req hubapi.SyncReq
			if err := json.NewDecoder(gz).Decode(&req); err != nil {
				t.Error(err)
				return
			}
			syncReqs = append(syncReqs, req)
			var resp hubapi.SyncResp
			if len(syncReqs) == 1 {
				resp = hubapi.SyncResp{
					Inputs: []hubapi.Input{{Domain: "linux/next/kasan", Prog: raw}},
					Repros: [][]byte{raw},
					More:   1,
				}
			}
			w.Header().Set("Content-Type", "application/json")
			if err := json.NewEncoder(w).Encode(resp); err != nil {
				t.Error(err)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	client, err := hubapi.NewClient("test-client", srv.URL, "test-secret")
	require.NoError(t, err)
	mgr := &fakeHubManager{}
	hc := &HubConnector{
		mgr:               mgr,
		target:            target,
		cfg:               &mgrconfig.Config{HubClient: "test-client", HubAddr: srv.URL, Name: "mgr-1"},
		domain:            "linux/upstream/kasan",
		enabledCalls:      map[*prog.Syscall]bool{call: true},
		fresh:             true,
		hubReproQueue:     make(chan *manager.Crash, 4),
		needMoreRepros:    func() bool { return true },
		client:            client,
		statRecvProg:      &stat.Val{},
		statRecvProgDrop:  &stat.Val{},
		statSendRepro:     &stat.Val{},
		statRecvRepro:     &stat.Val{},
		statRecvReproDrop: &stat.Val{},
	}

	// Failed connect preserves fresh.
	failNext = true
	require.Error(t, hc.connect(t.Context(), nil))
	assert.True(t, hc.fresh)

	// Successful connect uploads corpus and clears fresh.
	require.NoError(t, hc.connect(t.Context(), []*corpus.Item{{Prog: p}}))
	assert.False(t, hc.fresh)
	assert.Equal(t, "test-client", gotClient)
	assert.Equal(t, "mgr-1", gotManager)
	assert.Equal(t, [][]byte{raw}, gotConnect.Corpus)

	// Failed sync preserves newRepros for retry.
	hc.newRepros = [][]byte{raw}
	failNext = true
	require.ErrorContains(t, hc.sync(t.Context()), "409 Conflict")
	assert.Equal(t, [][]byte{raw}, hc.newRepros)

	// Successful sync paginates while More > 0 and only sends repros/NeedRepros on the first page.
	require.NoError(t, hc.sync(t.Context()))
	require.Len(t, syncReqs, 2)
	assert.True(t, syncReqs[0].NeedRepros)
	assert.Equal(t, [][]byte{raw}, syncReqs[0].Repros)
	assert.False(t, syncReqs[1].NeedRepros)
	assert.Empty(t, syncReqs[1].Repros)
	assert.Nil(t, hc.newRepros)
	assert.Len(t, mgr.candidates, 1)
	assert.Len(t, hc.hubReproQueue, 1)
}

type fakeHubManager struct {
	candidates []fuzzer.Candidate
}

func (m *fakeHubManager) getMinimizedCorpus() []*corpus.Item { return nil }

func (m *fakeHubManager) getNewRepros() [][]byte { return nil }

func (m *fakeHubManager) addNewCandidates(c []fuzzer.Candidate) {
	m.candidates = append(m.candidates, c...)
}

func (m *fakeHubManager) needMoreCandidates() bool { return true }

func (m *fakeHubManager) hubIsUnreachable() {}
