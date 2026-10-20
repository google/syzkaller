// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package boot runs smoke boot tests on built kernel images.
package boot

import (
	"fmt"

	"github.com/google/syzkaller/pkg/debugtracer"
	"github.com/google/syzkaller/pkg/instance"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/report"
)

// To prevent false positive results, demand that in order to be marked as FAILED,
// the test must fail 3 times in a row.
const retryCount = 3

// The base config may have more VMs, but we don't need that many.
const vmCount = 3

// Run completes cfg (overriding the VM count) and executes the smoke test,
// returning a non-nil *report.Report if the kernel failed to boot on all retryCount attempts,
// or nil if it booted successfully.
func Run(cfg *mgrconfig.Config, tracer debugtracer.DebugTracer) (*report.Report, error) {
	if tracer == nil {
		tracer = &debugtracer.NullTracer{}
	}
	if err := instance.OverrideVMCount(cfg, vmCount); err != nil {
		return nil, fmt.Errorf("failed to override VM count: %w", err)
	}
	if err := mgrconfig.Complete(cfg); err != nil {
		return nil, fmt.Errorf("failed to complete the config: %w", err)
	}

	var rep *report.Report
	for i := range retryCount {
		tracer.Logf("starting attempt #%d", i)
		var err error
		rep, err = instance.RunSmokeTest(cfg)
		if err != nil {
			return nil, fmt.Errorf("smoke test failed: %w", err)
		} else if rep == nil {
			return nil, nil
		}
		tracer.Logf("attempt failed: %q", rep.Title)
	}
	return rep, nil
}
