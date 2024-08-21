// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/google/syzkaller/pkg/asset"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
	"github.com/google/syzkaller/vm/vmimpl"
	"github.com/google/syzkaller/vm/vmtest"
)

func Test_Crash_FullTitle(t *testing.T) {
	crash := &Crash{}

	tests := []struct {
		name          string
		report        *report.Report
		fromDashboard bool
		fromHub       bool
		expected      string
	}{
		{
			name:     "report title is filled",
			report:   &report.Report{Title: "foo"},
			expected: "foo",
		},
		{
			name:          "report title fromDashboard",
			report:        &report.Report{},
			fromDashboard: true,
			expected:      fmt.Sprintf("dashboard crash %p", crash),
		},
		{
			name:     "report title fromHub",
			report:   &report.Report{},
			fromHub:  true,
			expected: fmt.Sprintf("crash from hub %p", crash),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.report.Title == "" && !tt.fromDashboard && !tt.fromHub {
				assert.Panics(t, func() { crash.FullTitle() })
			} else {
				crash.Report = tt.report
				crash.fromDashboard = tt.fromDashboard
				crash.fromHub = tt.fromHub

				title := crash.FullTitle()
				assert.Equal(t, tt.expected, title)
			}
		})
	}
}

func TestNewManagerService(t *testing.T) {
	initVM()

	reproMgr := &reproMgrMock{
		run: make(chan runCallback),
	}
	defaultCfg := mgrconfig.Config{
		Type:    targets.TestOS,
		Sandbox: "none",
		Derived: mgrconfig.Derived{
			TargetOS:     targets.TestOS,
			TargetArch:   targets.TestArch64,
			TargetVMArch: targets.TestArch64,
			SysTarget:    targets.Get(targets.TestOS, targets.TestArch64),
			Target:       &prog.Target{OS: targets.TestOS, Arch: targets.TestArch64},
			Timeouts:     targets.Timeouts{Slowdown: 1},
		},
	}

	tests := []struct {
		name           string
		mode           Mode
		modifyCfg      func() *mgrconfig.Config
		isFlagBenchSet bool
		expectedErr    error
		assertService  func(*service)
	}{
		{
			name: "err - invalid config",
			modifyCfg: func() *mgrconfig.Config {
				return &mgrconfig.Config{}
			},
			assertService: func(s *service) {
				assert.Nil(t, s)
			},
			expectedErr: fmt.Errorf("unknown instance type ''"),
		},
		{
			name: "ok - w/o dashboard, assetStorage",
			modifyCfg: func() *mgrconfig.Config {
				return &defaultCfg
			},
			assertService: func(s *service) {
				assert.Nil(t, s.assetStorage)
				assert.Nil(t, s.dash)
				assert.Nil(t, s.dashRepro)
			},
		},
		{
			name: "ok - w/o dashboard",
			modifyCfg: func() *mgrconfig.Config {
				cfg := defaultCfg
				cfg.AssetStorage = &asset.Config{UploadTo: "dummy://"}
				return &cfg
			},
			assertService: func(s *service) {
				assert.Nil(t, s.dash)
				assert.Nil(t, s.dashRepro)
			},
		},
		{
			name: "ok - w/o dashboard, vmPool",
			modifyCfg: func() *mgrconfig.Config {
				cfg := defaultCfg
				cfg.AssetStorage = &asset.Config{UploadTo: "dummy://"}
				cfg.VMLess = true
				return &cfg
			},
			assertService: func(s *service) {
				assert.Nil(t, s.dash)
				assert.Nil(t, s.dashRepro)
				assert.Nil(t, s.vmPool)
				assert.Nil(t, s.reproMgr)
			},
		},
		{
			name: "ok - all deps are set except dash",
			modifyCfg: func() *mgrconfig.Config {
				// Intentionally modify defaultCfg for the last test case.
				cfg := &defaultCfg
				cfg.AssetStorage = &asset.Config{UploadTo: "dummy://"}
				cfg.DashboardAddr = "addr"
				cfg.DashboardKey = "key"
				cfg.DashboardOnlyRepro = true
				return cfg
			},
			assertService: func(s *service) {
				assert.Nil(t, s.dash)
			},
		},
		{
			name: "ok - all deps are set",
			modifyCfg: func() *mgrconfig.Config {
				cfg := defaultCfg
				cfg.DashboardOnlyRepro = false
				return &cfg
			},
			assertService: func(s *service) {
				assert.NotNil(t, s.dash)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := tt.modifyCfg()
			mgr := newManager(cfg, ModeRunTests)
			service, err := newManagerService(cfg, mgr, reproMgr)
			assert.Equal(t, tt.expectedErr, err)
			if tt.expectedErr != nil {
				return
			}
			tt.assertService(service)
		})
	}
}

func initVM() {
	ctor := func(env *vmimpl.Env) (vmimpl.Pool, error) {
		return &vmtest.TestPool{}, nil
	}
	vmimpl.Register(targets.TestOS, vmimpl.Type{
		Ctor:        ctor,
		Preemptible: true,
	})
}
