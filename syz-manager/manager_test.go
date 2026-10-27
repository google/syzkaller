// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"regexp"
	"testing"

	"github.com/google/syzkaller/pkg/manager"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/report"
	"github.com/stretchr/testify/assert"
)

func TestNeedReproReproduceOnly(t *testing.T) {
	mgr := &Manager{cfg: &mgrconfig.Config{
		Reproduce:     true,
		ReproduceOnly: []string{"^KASAN:"},
		Derived: mgrconfig.Derived{
			ReproduceOnlyRe: regexp.MustCompile("^KASAN:"),
		},
	}}
	crash := func(title string, hub, dash, manual bool) *manager.Crash {
		return &manager.Crash{
			FromHub:       hub,
			FromDashboard: dash,
			Manual:        manual,
			Report:        &report.Report{Title: title},
		}
	}
	// FromHub/FromDashboard crashes return true right after the filter,
	// so these don't need a fully set up Manager.
	assert.True(t, mgr.NeedRepro(crash("KASAN: foo", false, true, false)))
	assert.False(t, mgr.NeedRepro(crash("WARNING in foo", false, true, false)))
	assert.False(t, mgr.NeedRepro(crash("WARNING in foo", true, false, false)))
	assert.True(t, mgr.NeedRepro(crash("WARNING in foo", false, true, true)))
	mgr.cfg.Reproduce = false
	assert.False(t, mgr.NeedRepro(crash("WARNING in foo", false, true, true)))
}
