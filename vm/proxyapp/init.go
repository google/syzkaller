// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package proxyapp

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"github.com/google/syzkaller/pkg/config"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/vm/vmimpl"
)

func makeDefaultParams() *proxyAppParams {
	return &proxyAppParams{
		CommandRunner:  osutilCommandContext,
		InitRetryDelay: 10 * time.Second,
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

type Config struct {
	Command        string          `json:"cmd"`
	ProxyAppConfig json.RawMessage `json:"config"`
}

func parseConfig(conf []byte) (*Config, error) {
	vmCfg := new(Config)
	if err := config.LoadData(conf, vmCfg); err != nil {
		return nil, fmt.Errorf("failed to parseConfig(): %w", err)
	}
	return vmCfg, nil
}
