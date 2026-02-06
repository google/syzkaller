// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package symbolizer_test

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/symbolizer"
	"github.com/google/syzkaller/sys/targets"
)

func BenchmarkMake(b *testing.B) {
	vmlinux := os.Getenv("VMLINUX")
	if vmlinux == "" {
		vmlinux = filepath.Join(os.Getenv("HOME"), "projects/fuzzing-qemu/linux-stable/vmlinux")
	}
	if _, err := os.Stat(vmlinux); err != nil {
		b.Skipf("vmlinux not found at %v: %v", vmlinux, err)
	}

	target := targets.Get("linux", "amd64")
	target.KernelObject = vmlinux

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		start := time.Now()
		symb, err := symbolizer.Make(target, vmlinux)
		if err != nil {
			b.Fatalf("failed to create symbolizer: %v", err)
		}
		b.ReportMetric(float64(time.Since(start).Seconds()), "sec/op")
		symb.Close()
	}
}
