// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package proxyapp

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseConfig(t *testing.T) {
	tests := []struct {
		name       string
		data       string
		wantConfig *Config
		wantErr    bool
	}{
		{
			name: "test cmd and rpc_server_uri specified Ok",
			data: `{
				"cmd": "/path/to/proxyapp_binary",
				"rpc_server_uri": "127.0.0.1:1234"}`,
			wantConfig: &Config{
				Command:      "/path/to/proxyapp_binary",
				RPCServerURI: "127.0.0.1:1234",
			},
			wantErr: false,
		},
		{
			name: "only cmd specified Ok",
			data: `{"cmd": "/path/to/proxyapp_binary"}`,
			wantConfig: &Config{
				Command:      "/path/to/proxyapp_binary",
				RPCServerURI: "",
			},
			wantErr: false,
		},
		{
			name: "only rpc_server_uri specified Ok",
			data: `{"rpc_server_uri": "127.0.0.1:1234"}`,
			wantConfig: &Config{
				Command:      "",
				RPCServerURI: "127.0.0.1:1234",
			},
			wantErr: false,
		},
		{
			name:       "cmd OR rpc_server_uri are needed",
			data:       `{}`,
			wantConfig: nil,
			wantErr:    true,
		},
		{
			name:       "rpc address format Ok",
			data:       `{"rpc_server_uri": "127.0.0.1:1234"}`,
			wantConfig: &Config{RPCServerURI: "127.0.0.1:1234"},
			wantErr:    false,
		},
		{
			name:       "rpc address format bad",
			data:       `{"rpc_server_uri": "http://127.0.0.1:1234"}`,
			wantConfig: nil,
			wantErr:    true,
		},
		{
			name: "remote plugin config Ok",
			data: `{"rpc_server_uri": "127.0.0.1:1234",
						  "config": {"param": 1}}`,
			wantConfig: &Config{
				RPCServerURI:   "127.0.0.1:1234",
				ProxyAppConfig: []byte(`{"param": 1}`),
			},
			wantErr: false,
		},
		{
			name: "remote plugin config is optional",
			data: `{"rpc_server_uri": "127.0.0.1:1234"}`,
			wantConfig: &Config{
				RPCServerURI:   "127.0.0.1:1234",
				ProxyAppConfig: nil,
			},
			wantErr: false,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(tt *testing.T) {
			cfg, err := parseConfig([]byte(test.data))
			assert.Equal(tt, err != nil, test.wantErr)
			assert.Equal(tt, test.wantConfig, cfg)
		})
	}
}

func TestURIParseErr(t *testing.T) {
	assert.Nil(t, URIParseErr("127.0.0.1:1234"))
	assert.Nil(t, URIParseErr("domain_name:1234"))

	assert.NotNil(t, URIParseErr("http://domain_name:1234"))
	assert.NotNil(t, URIParseErr("http://127.0.0.1:1234"))
	assert.NotNil(t, URIParseErr("127.0.0.1"))
}
