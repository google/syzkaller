// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/auth"
	"github.com/google/syzkaller/pkg/hubapi"
	"github.com/google/syzkaller/syz-hub/state"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuth(t *testing.T) {
	hub := &Hub{
		keys: map[string]string{
			"foo": "1234",
			"bar": "abcd",
		},
	}
	tests := []struct {
		client  string
		key     string
		manager string
		result  string
		ok      bool
	}{
		{
			client:  "",
			key:     "",
			manager: "",
			result:  "",
			ok:      false,
		},
		{
			client:  "",
			key:     "1234",
			manager: "manager",
			result:  "",
			ok:      false,
		},
		{
			client:  "foo",
			key:     "",
			manager: "foo",
			result:  "",
			ok:      false,
		},
		{
			client:  "foo",
			key:     "123",
			manager: "foo",
			result:  "",
			ok:      false,
		},
		{
			client:  "foo",
			key:     "abcd",
			manager: "foo",
			result:  "",
			ok:      false,
		},
		{
			client:  "foo",
			key:     "1234",
			manager: "foo",
			result:  "foo",
			ok:      true,
		},
		{
			client:  "foo",
			key:     "1234",
			manager: "foo-suffix",
			result:  "foo-suffix",
			ok:      true,
		},
		{
			client:  "foo",
			key:     "1234",
			manager: "",
			result:  "foo",
			ok:      true,
		},
		{
			client:  "foo",
			key:     "1234",
			manager: "bar",
			result:  "",
			ok:      false,
		},
		{
			client:  "foo",
			key:     "1234",
			manager: "foo/bar",
			result:  "",
			ok:      false,
		},
		{
			client:  "foo",
			key:     "1234",
			manager: `foo\bar`,
			result:  "",
			ok:      false,
		},
		{
			client:  "foo",
			key:     "1234",
			manager: "foo/../../tmp/pwn",
			result:  "",
			ok:      false,
		},
		{
			client:  "foo",
			key:     "1234",
			manager: "foo-5.15_kasan",
			result:  "foo-5.15_kasan",
			ok:      true,
		},
	}
	for _, test := range tests {
		t.Run(fmt.Sprintf("%q/%q/%q", test.client, test.key, test.manager), func(t *testing.T) {
			manager, err := hub.checkManager(test.client, test.key, test.manager)
			if !test.ok && err == nil {
				t.Fatalf("auth is expected to fail, but it did not")
			}
			if test.ok && err != nil {
				t.Fatalf("auth is not expected to fail, but it did: %v", err)
			}
			if manager != test.result {
				t.Fatalf("got bad manager %q, want %q", manager, test.result)
			}
		})
	}
}

func TestHubConnectSyncAndHTTP(t *testing.T) {
	t.Parallel()
	hub, srv := newTestHubServer(t, map[string]string{
		"client1": "secret1",
		"client2": "secret2",
	})

	c1, err := hubapi.NewClient("client1", srv.URL, "secret1", hubapi.WithHTTPClient(srv.Client()))
	require.NoError(t, err)
	c2, err := hubapi.NewClient("client2", srv.URL, "secret2", hubapi.WithHTTPClient(srv.Client()))
	require.NoError(t, err)

	require.NoError(t, c1.Connect(t.Context(), &hubapi.ConnectReq{
		Manager: "client1-mgr",
		HTTP:    "http://127.0.0.1:10001",
		Domain:  "dom1",
		Fresh:   true,
		Calls:   []string{"open", "read"},
		Corpus:  [][]byte{[]byte("open(0x0)")},
	}))
	require.NoError(t, c2.Connect(t.Context(), &hubapi.ConnectReq{
		Manager: "client2-mgr",
		HTTP:    "http://127.0.0.1:10002",
		Fresh:   true,
		Calls:   []string{"open", "read"},
		Corpus:  [][]byte{[]byte("read(0x1)")},
	}))

	syncResp2, err := c2.Sync(t.Context(), &hubapi.SyncReq{
		Manager: "client2-mgr",
		Repros:  [][]byte{[]byte("open(0x0)\nread(0x1)")},
	})
	require.NoError(t, err)
	assert.Equal(t, []hubapi.Input{
		{Domain: "dom1", Prog: []byte("open(0x0)")},
	}, syncResp2.Inputs)

	syncResp1, err := c1.Sync(t.Context(), &hubapi.SyncReq{
		Manager:    "client1-mgr",
		NeedRepros: true,
	})
	require.NoError(t, err)
	assert.Equal(t, []hubapi.Input{
		{Domain: "", Prog: []byte("read(0x1)")},
	}, syncResp1.Inputs)
	assert.Equal(t, [][]byte{[]byte("open(0x0)\nread(0x1)")}, syncResp1.Repros)

	// Verify the external API handler does not expose the unauthenticated summary UI.
	rootResp, err := srv.Client().Get(srv.URL + "/")
	require.NoError(t, err)
	rootResp.Body.Close()
	assert.Equal(t, http.StatusNotFound, rootResp.StatusCode)

	// Verify HTTP summary renders manager stats.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	hub.httpSummary(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "syz-hub")
	assert.Contains(t, rec.Body.String(), "client1-mgr")
	assert.Contains(t, rec.Body.String(), "client2-mgr")
}

func TestLoadConfig(t *testing.T) {
	rawCfg := `{
		"http": ":50000",
		"rpc": ":50001",
		"workdir": "/workdir",
		"clients": [
			{"name": "plain", "key": "plain-secret"},
			{"name": "oauth", "key": "OauthSubject:12345"},
			{"name": "trimmed", "key": "  secret-with-spaces\n"}
		]
	}`
	t.Setenv("SYZ_HUB_TEST_CONFIG", rawCfg)

	wantKeys := map[string]string{
		"plain":   "plain-secret",
		"oauth":   "OauthSubject:12345",
		"trimmed": "secret-with-spaces",
	}

	cfg, keys, err := loadConfig(context.Background(), "env:SYZ_HUB_TEST_CONFIG")
	require.NoError(t, err)
	assert.Equal(t, ":50000", cfg.HTTP)
	assert.Equal(t, ":50001", cfg.RPC)
	assert.Equal(t, "/workdir", cfg.Workdir)
	assert.Equal(t, wantKeys, keys)

	cfgFile := filepath.Join(t.TempDir(), "hub-config.json")
	require.NoError(t, os.WriteFile(cfgFile, []byte(rawCfg), 0600))
	cfgFromFile, keysFromFile, err := loadConfig(context.Background(), cfgFile)
	require.NoError(t, err)
	assert.Equal(t, cfg, cfgFromFile)
	assert.Equal(t, wantKeys, keysFromFile)

	_, _, err = loadConfig(context.Background(), filepath.Join(t.TempDir(), "missing.json"))
	assert.Error(t, err)

	t.Setenv("SYZ_HUB_EMPTY_CONFIG", "   \n")
	_, _, err = loadConfig(context.Background(), "env:SYZ_HUB_EMPTY_CONFIG")
	assert.ErrorContains(t, err, "config env:SYZ_HUB_EMPTY_CONFIG is empty")

	t.Setenv("SYZ_HUB_INVALID_JSON", "{invalid")
	_, _, err = loadConfig(context.Background(), "env:SYZ_HUB_INVALID_JSON")
	assert.Error(t, err)

	for _, tc := range []struct {
		name    string
		clients string
		wantErr string
	}{
		{
			name:    "empty_name",
			clients: `[{"name": "", "key": "secret1"}]`,
			wantErr: "invalid client name",
		},
		{
			name:    "whitespace_name",
			clients: `[{"name": "   ", "key": "secret1"}]`,
			wantErr: "invalid client name",
		},
		{
			name:    "empty_key",
			clients: `[{"name": "emptyclient", "key": "   \n"}]`,
			wantErr: "client emptyclient: empty key",
		},
		{
			name:    "duplicate_client",
			clients: `[{"name": "dup", "key": "secret1"}, {"name": "dup", "key": "secret2"}]`,
			wantErr: "duplicate client dup",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SYZ_HUB_BAD_CLIENT_CFG", `{
				"http": ":50000",
				"rpc": ":50001",
				"workdir": "/workdir",
				"clients": `+tc.clients+`
			}`)
			_, _, err := loadConfig(context.Background(), "env:SYZ_HUB_BAD_CLIENT_CFG")
			assert.ErrorContains(t, err, tc.wantErr)
		})
	}
}

func TestHTTPOAuthAuth(t *testing.T) {
	t.Parallel()
	claimsJSON, err := json.Marshal(struct {
		Exp int64 `json:"exp"`
	}{
		Exp: time.Now().Add(time.Hour).Unix(),
	})
	require.NoError(t, err)
	fakeJWT := "hdr." + base64.RawURLEncoding.EncodeToString(claimsJSON) + ".sig"

	tokenInfoSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
			return
		}
		assert.Equal(t, fakeJWT, r.FormValue("id_token"))
		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(map[string]string{
			"sub": "123456",
			"aud": auth.DashboardAudience,
			"exp": fmt.Sprint(time.Now().Add(time.Hour).Unix()),
		}); err != nil {
			t.Error(err)
		}
	}))
	t.Cleanup(tokenInfoSrv.Close)

	_, srv := newTestHubServer(t, map[string]string{
		"oauth-client": auth.OauthMagic + "123456",
	}, auth.MakeEndpoint(tokenInfoSrv.URL))

	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		if req.URL.Host == "metadata.google.internal" {
			return &http.Response{
				StatusCode: http.StatusOK,
				Body:       io.NopCloser(strings.NewReader(fakeJWT)),
			}, nil
		}
		return http.DefaultTransport.RoundTrip(req)
	})
	client, err := hubapi.NewClient("oauth-client", srv.URL, "",
		hubapi.WithHTTPClient(&http.Client{Transport: transport}))
	require.NoError(t, err)

	require.NoError(t, client.Connect(t.Context(), &hubapi.ConnectReq{
		Manager: "oauth-client-mgr",
		Calls:   []string{"open"},
	}))
	resp, err := client.Sync(t.Context(), &hubapi.SyncReq{Manager: "oauth-client-mgr"})
	require.NoError(t, err)
	assert.Empty(t, resp.Inputs)
}

func TestHTTPProtocolErrors(t *testing.T) {
	t.Parallel()
	_, srv := newTestHubServer(t, map[string]string{"client1": "secret1"})

	tests := []struct {
		name       string
		method     string
		path       string
		client     string
		manager    string
		authHeader string
		encoding   string
		body       []byte
		wantStatus int
	}{
		{
			name:       "get_not_allowed",
			method:     http.MethodGet,
			path:       hubapi.PathConnect,
			client:     "client1",
			authHeader: "Bearer secret1",
			wantStatus: http.StatusMethodNotAllowed,
		},
		{
			name:       "missing_auth",
			method:     http.MethodPost,
			path:       hubapi.PathConnect,
			client:     "client1",
			body:       []byte(`{}`),
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "wrong_secret_before_body_decode",
			method:     http.MethodPost,
			path:       hubapi.PathConnect,
			client:     "client1",
			manager:    "client1",
			authHeader: "Bearer wrong",
			encoding:   "br",
			body:       []byte("not-valid-body"),
			wantStatus: http.StatusUnauthorized,
		},
		{
			name:       "unsupported_encoding",
			method:     http.MethodPost,
			path:       hubapi.PathConnect,
			client:     "client1",
			authHeader: "Bearer secret1",
			encoding:   "br",
			body:       []byte(`{}`),
			wantStatus: http.StatusUnsupportedMediaType,
		},
		{
			name:       "invalid_gzip",
			method:     http.MethodPost,
			path:       hubapi.PathConnect,
			client:     "client1",
			authHeader: "Bearer secret1",
			encoding:   "gzip",
			body:       []byte("not-gzip"),
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "invalid_json",
			method:     http.MethodPost,
			path:       hubapi.PathConnect,
			client:     "client1",
			authHeader: "Bearer secret1",
			body:       []byte("{invalid"),
			wantStatus: http.StatusBadRequest,
		},
		{
			name:       "sync_before_connect",
			method:     http.MethodPost,
			path:       hubapi.PathSync,
			client:     "client1",
			manager:    "client1",
			authHeader: "Bearer secret1",
			body:       []byte(`{}`),
			wantStatus: http.StatusConflict,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			req, err := http.NewRequestWithContext(t.Context(), tc.method, srv.URL+tc.path,
				bytes.NewReader(tc.body))
			require.NoError(t, err)
			if tc.client != "" {
				req.Header.Set(hubapi.HeaderClient, tc.client)
			}
			if tc.manager != "" {
				req.Header.Set(hubapi.HeaderManager, tc.manager)
			}
			if tc.authHeader != "" {
				req.Header.Set("Authorization", tc.authHeader)
			}
			if tc.encoding != "" {
				req.Header.Set("Content-Encoding", tc.encoding)
			}
			resp, err := srv.Client().Do(req)
			require.NoError(t, err)
			resp.Body.Close()
			assert.Equal(t, tc.wantStatus, resp.StatusCode)
		})
	}
}

func newTestHubServer(t *testing.T, keys map[string]string, endpoint ...auth.Endpoint) (*Hub, *httptest.Server) {
	t.Helper()
	st, err := state.Make(t.TempDir())
	require.NoError(t, err)
	hub := &Hub{
		st:   st,
		keys: keys,
	}
	if len(endpoint) > 0 {
		hub.auth = endpoint[0]
	}
	srv := httptest.NewServer(hub.apiHandler())
	t.Cleanup(srv.Close)
	return hub, srv
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return fn(req)
}
