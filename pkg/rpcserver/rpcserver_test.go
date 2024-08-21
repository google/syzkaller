// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package rpcserver

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/google/syzkaller/pkg/cover/backend"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

func TestNew(t *testing.T) {
	defaultCfg := mgrconfig.Config{
		Type:    targets.Linux,
		Sandbox: "none",
		Derived: mgrconfig.Derived{
			TargetOS:     targets.TestOS,
			TargetArch:   targets.TestArch64,
			TargetVMArch: targets.TestArch64,
			Timeouts:     targets.Timeouts{Slowdown: 1},
		},
	}

	nilServer := func(s *Server) {
		assert.Nil(t, s)
	}

	tests := []struct {
		name              string
		modifyCfg         func() *mgrconfig.Config
		debug             bool
		expectedServCheck func(*Server)
		expectsErr        bool
		expectedErr       error
	}{
		{
			name: "unknown PCBase",
			modifyCfg: func() *mgrconfig.Config {
				cfg := defaultCfg
				cfg.KernelObj = "test"
				return &cfg
			},
			expectedServCheck: nilServer,
			expectedErr:       backend.ErrUnknownPCBase,
		},
		{
			name: "unknown Sandbox",
			modifyCfg: func() *mgrconfig.Config {
				cfg := defaultCfg
				cfg.Sandbox = "unknown"
				return &cfg
			},
			expectedServCheck: nilServer,
			expectsErr:        true,
		},
		{
			name: "unknown target OS and VMArch",
			modifyCfg: func() *mgrconfig.Config {
				cfg := defaultCfg
				cfg.TargetVMArch = "unknown"
				return &cfg
			},
			expectedServCheck: nilServer,
			expectsErr:        true,
		},
		{
			name: "experimental features",
			modifyCfg: func() *mgrconfig.Config {
				cfg := defaultCfg
				cfg.Experimental = mgrconfig.Experimental{
					RemoteCover: false,
					CoverEdges:  true,
				}
				return &cfg
			},
			expectedServCheck: func(s *Server) {
				assert.Equal(t, s.cfg.Config.Features, flatrpc.AllFeatures&(^flatrpc.FeatureExtraCoverage))
				assert.True(t, s.cfg.UseCoverEdges)
				assert.True(t, s.cfg.FilterSignal)
				assert.Nil(t, s.serv) // call Start() to start rpc server
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := tt.modifyCfg()

			var err error
			cfg.Target, err = prog.GetTarget(cfg.TargetOS, cfg.TargetArch)
			assert.NoError(t, err)

			serv, err := New(cfg, nil, tt.debug)

			tt.expectedServCheck(serv)

			if tt.expectedErr != nil {
				assert.Equal(t, tt.expectedErr, err)
			} else if tt.expectsErr {
				assert.Error(t, err)
			} else {
				assert.Nil(t, err)
			}
		})
	}
}
