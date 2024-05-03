// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package proxyapp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"time"

	"github.com/google/syzkaller/pkg/config"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/vm/vmimpl"
)

func makeDefaultParams() *proxyAppParams {
	return &proxyAppParams{
		CommandRunner:  osutilCommandContext,
		InitRetryDelay: 10 * time.Second,
		LogOutput:      os.Stdout,
	}
}

func init() {
	vmimpl.Register(
		"proxyapp",
		func(env *vmimpl.Env) (vmimpl.Pool, error) {
			return ctor(makeDefaultParams(), env)
		},
		false)
}

// Package configuration VARs are mostly needed for tests.
type proxyAppParams struct {
	CommandRunner  func(context.Context, string, ...string) subProcessCmd
	InitRetryDelay time.Duration
	LogOutput      io.Writer
}

func osutilCommandContext(ctx context.Context, bin string, args ...string) subProcessCmd {
	return osutil.CommandContext(ctx, bin, args...)
}

type subProcessCmd interface {
	StdinPipe() (io.WriteCloser, error)
	StdoutPipe() (io.ReadCloser, error)
	StderrPipe() (io.ReadCloser, error)
	Start() error
	Wait() error
}

// Config is valid if at least cmd or rpc_server_uri specified.
type Config struct {
	// cmd is the optional command needed to initialize plugin.
	// By default we'll connect to its std[in, out, err].
	Command string `json:"cmd"`
	// rpc_server_uri is used to specify plugin endpoint address.
	// if not specified, we'll connect to the plugin by std[in, out, err].
	RPCServerURI string `json:"rpc_server_uri"`
	// security can be one of "none", "tls" (for server TLS) and "mtls" for mutal
	// TLS.
	Security string `json:"security"`
	// server_tls_cert points a TLS certificate used to authenticate the server.
	// If not provided, the default system certificate pool will be used.
	ServerTLSCert string `json:"server_tls_cert"`
	// transfer_file_content will send the file content as a byte array in
	// addition to the filename.
	TransferFileContent bool `json:"transfer_file_content"`
	// config is an optional remote plugin config
	ProxyAppConfig json.RawMessage `json:"config"`
}

func parseConfig(conf []byte) (*Config, error) {
	vmCfg := new(Config)
	if err := config.LoadData(conf, vmCfg); err != nil {
		return nil, fmt.Errorf("failed to parseConfig(): %w", err)
	}

	if vmCfg.RPCServerURI == "" && vmCfg.Command == "" {
		return nil, errors.New("failed to parseConfig(): neither 'cmd' nor 'rpc_server_uri' specified for plugin")
	}

	if vmCfg.RPCServerURI != "" && URIParseErr(vmCfg.RPCServerURI) != nil {
		return nil, fmt.Errorf("failed to parseConfig(): %w", URIParseErr(vmCfg.RPCServerURI))
	}

	return vmCfg, nil
}

func URIParseErr(uri string) error {
	dest, err := url.Parse("http://" + uri)
	if err != nil || dest.Port() == "" || dest.Host != uri {
		return fmt.Errorf("bad uri (%v), host:port were expected", uri)
	}
	return nil
}
