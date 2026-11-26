// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package hubapi

import (
	"compress/gzip"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewClientValidation(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		client string
		addr   string
	}{
		{name: "empty_client", client: "", addr: "https://hub.example.com"},
		{name: "empty_addr", client: "mgr", addr: ""},
		{name: "missing_scheme", client: "mgr", addr: "1.2.3.4:50001"},
		{name: "unsupported_scheme", client: "mgr", addr: "ftp://hub.example.com"},
		{name: "missing_host", client: "mgr", addr: "https://"},
		{name: "userinfo_in_url", client: "mgr", addr: "https://user:pass@hub.example.com"},
		{name: "query_in_url", client: "mgr", addr: "https://hub.example.com?foo=bar"},
		{name: "trailing_question_mark", client: "mgr", addr: "https://hub.example.com?"},
		{name: "fragment_in_url", client: "mgr", addr: "https://hub.example.com#frag"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			_, err := NewClient(tc.client, tc.addr, "secret")
			require.Error(t, err)
		})
	}
}

func TestClientRoundTrip(t *testing.T) {
	t.Parallel()
	var gotConnect ConnectReq
	var gotConnectClient, gotConnectManager string
	var gotSync SyncReq
	var gotSyncClient, gotSyncManager string
	wantResp := SyncResp{
		Inputs: []Input{{Domain: "linux/upstream", Prog: []byte("open(0x0)\n")}},
		Repros: [][]byte{[]byte("close(0x0)\n")},
		More:   7,
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		assert.Equal(t, "application/json", r.Header.Get("Content-Type"))
		assert.Equal(t, "gzip", r.Header.Get("Content-Encoding"))
		if r.URL.Path == "/redirect"+PathConnect {
			http.Redirect(w, r, "/prefix"+PathConnect, http.StatusTemporaryRedirect)
			return
		}
		if r.Header.Get("Authorization") != "Bearer secret-key" {
			http.Error(w, "unauthorized manager", http.StatusUnauthorized)
			return
		}
		switch r.URL.Path {
		case "/prefix" + PathConnect:
			gotConnectClient = r.Header.Get(HeaderClient)
			gotConnectManager = r.Header.Get(HeaderManager)
			decodeGzipJSON(t, r, &gotConnect)
			w.WriteHeader(http.StatusOK)
		case "/prefix" + PathSync:
			gotSyncClient = r.Header.Get(HeaderClient)
			gotSyncManager = r.Header.Get(HeaderManager)
			decodeGzipJSON(t, r, &gotSync)
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Content-Encoding", "gzip")
			gz := gzip.NewWriter(w)
			if err := json.NewEncoder(gz).Encode(&wantResp); err != nil {
				t.Error(err)
				return
			}
			if err := gz.Close(); err != nil {
				t.Error(err)
			}
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)

	client, err := NewClient("client1", srv.URL+"/prefix/", "secret-key")
	require.NoError(t, err)

	connectReq := &ConnectReq{
		Manager: "client1-kasan",
		HTTP:    "http://manager:8080",
		Domain:  "linux/kasan",
		Fresh:   true,
		Calls:   []string{"open", "read"},
		Corpus:  [][]byte{[]byte("read(0x0)\n")},
	}
	require.NoError(t, client.Connect(t.Context(), connectReq))
	assert.Equal(t, "client1", gotConnectClient)
	assert.Equal(t, "client1-kasan", gotConnectManager)
	assert.Equal(t, connectReq.Corpus, gotConnect.Corpus)

	syncReq := &SyncReq{
		Manager:    "client1-kasan",
		NeedRepros: true,
		Repros:     [][]byte{[]byte("open(0x2)\n")},
	}
	gotResp, err := client.Sync(t.Context(), syncReq)
	require.NoError(t, err)
	assert.Equal(t, "client1", gotSyncClient)
	assert.Equal(t, "client1-kasan", gotSyncManager)
	assert.Equal(t, syncReq.Repros, gotSync.Repros)
	assert.Equal(t, &wantResp, gotResp)

	require.Error(t, client.Connect(t.Context(), nil))
	_, err = client.Sync(t.Context(), nil)
	require.Error(t, err)

	badClient, err := NewClient("client1", srv.URL+"/prefix", "wrong-key")
	require.NoError(t, err)
	err = badClient.Connect(t.Context(), &ConnectReq{Manager: "client1"})
	require.ErrorContains(t, err, "401 Unauthorized: unauthorized manager")

	redirectClient, err := NewClient("client1", srv.URL+"/redirect", "secret-key")
	require.NoError(t, err)
	err = redirectClient.Connect(t.Context(), &ConnectReq{Manager: "client1"})
	require.ErrorContains(t, err, "unexpected redirect")

	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	require.ErrorIs(t, client.Connect(ctx, &ConnectReq{Manager: "client1"}), context.Canceled)
}

func TestWithHTTPClientOAuth(t *testing.T) {
	t.Parallel()
	claimsJSON, err := json.Marshal(struct {
		Exp int64 `json:"exp"`
	}{
		Exp: time.Now().Add(time.Hour).Unix(),
	})
	require.NoError(t, err)
	fakeJWT := "hdr." + base64.RawURLEncoding.EncodeToString(claimsJSON) + ".sig"

	var gotAuth, gotClient, gotManager string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotClient = r.Header.Get(HeaderClient)
		gotManager = r.Header.Get(HeaderManager)
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(srv.Close)

	var metadataCalled bool
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Host == "metadata.google.internal" {
			metadataCalled = true
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(fakeJWT)),
			}, nil
		}
		return http.DefaultTransport.RoundTrip(req)
	})

	client, err := NewClient("oauth-client", srv.URL, "",
		WithHTTPClient(&http.Client{Transport: transport}))
	require.NoError(t, err)
	require.NoError(t, client.Connect(t.Context(), &ConnectReq{
		Manager: "oauth-client-mgr",
		Calls:   []string{"open"},
	}))
	assert.True(t, metadataCalled)
	assert.Equal(t, "Bearer "+fakeJWT, gotAuth)
	assert.Equal(t, "oauth-client", gotClient)
	assert.Equal(t, "oauth-client-mgr", gotManager)
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}

func decodeGzipJSON(t *testing.T, r *http.Request, dst any) {
	t.Helper()
	gz, err := gzip.NewReader(r.Body)
	if err != nil {
		t.Error(err)
		return
	}
	defer gz.Close()
	if err := json.NewDecoder(gz).Decode(dst); err != nil {
		t.Error(err)
	}
}
