// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/syzkaller/pkg/rpctype"
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
	st, err := state.Make(t.TempDir())
	require.NoError(t, err)
	hub := &Hub{
		st: st,
		keys: map[string]string{
			"client1": "secret1",
			"client2": "secret2",
		},
	}

	// Connect client1 (with domain) and client2 (without domain).
	require.NoError(t, hub.Connect(&rpctype.HubConnectArgs{
		Client:  "client1",
		Key:     "secret1",
		Manager: "client1-mgr",
		HTTP:    "http://127.0.0.1:10001",
		Domain:  "dom1",
		Fresh:   true,
		Calls:   []string{"open", "read"},
		Corpus:  [][]byte{[]byte("open(0x0)")},
	}, new(int)))

	require.NoError(t, hub.Connect(&rpctype.HubConnectArgs{
		Client:  "client2",
		Key:     "secret2",
		Manager: "client2-mgr",
		HTTP:    "http://127.0.0.1:10002",
		Fresh:   true,
		Calls:   []string{"open", "read"},
	}, new(int)))

	// client2 has an empty domain, so Sync populates r.Progs instead of r.Inputs.
	syncRes2 := new(rpctype.HubSyncRes)
	require.NoError(t, hub.Sync(&rpctype.HubSyncArgs{
		Client:  "client2",
		Key:     "secret2",
		Manager: "client2-mgr",
		Add:     [][]byte{[]byte("read(0x1)")},
		Repros:  [][]byte{[]byte("open(0x0)\nread(0x1)")},
	}, syncRes2))
	assert.Equal(t, [][]byte{[]byte("open(0x0)")}, syncRes2.Progs)
	assert.Empty(t, syncRes2.Inputs)

	// client1 has a domain and requests repros, so Sync populates r.Inputs and r.Repros.
	syncRes1 := new(rpctype.HubSyncRes)
	require.NoError(t, hub.Sync(&rpctype.HubSyncArgs{
		Client:     "client1",
		Key:        "secret1",
		Manager:    "client1-mgr",
		NeedRepros: true,
	}, syncRes1))
	assert.Equal(t, []rpctype.HubInput{
		{Domain: "", Prog: []byte("read(0x1)")},
	}, syncRes1.Inputs)
	assert.Empty(t, syncRes1.Progs)
	assert.Equal(t, [][]byte{[]byte("open(0x0)\nread(0x1)")}, syncRes1.Repros)

	// Verify HTTP summary renders manager stats.
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()
	hub.httpSummary(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Contains(t, rec.Body.String(), "client1-mgr")
	assert.Contains(t, rec.Body.String(), "client2-mgr")
}

func TestLoadConfigAndResolveClientKeys(t *testing.T) {
	t.Setenv("SYZ_HUB_TEST_SECRET", "  resolved-from-env\n")
	rawCfg := `{
		"http": ":50000",
		"rpc": ":50001",
		"workdir": "/workdir",
		"clients": [
			{"name": "plain", "key": "plain-secret"},
			{"name": "oauth", "key": "OauthSubject:12345"},
			{"name": "envclient", "key": "env:SYZ_HUB_TEST_SECRET"}
		]
	}`
	t.Setenv("SYZ_HUB_TEST_CONFIG", rawCfg)

	wantKeys := map[string]string{
		"plain":     "plain-secret",
		"oauth":     "OauthSubject:12345",
		"envclient": "resolved-from-env",
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

	t.Setenv("SYZ_HUB_EMPTY_SECRET", "   \n")
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
			clients: `[{"name": "emptyclient", "key": "env:SYZ_HUB_EMPTY_SECRET"}]`,
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
