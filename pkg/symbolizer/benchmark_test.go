// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package symbolizer_test

import (
	"bufio"
	"bytes"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/symbolizer"
	"github.com/google/syzkaller/sys/targets"
)

func BenchmarkSymbolize(b *testing.B) {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		b.Skip("skipping on non-linux/amd64")
	}

	// Find vmlinux.
	vmlinux := os.Getenv("VMLINUX")
	if vmlinux == "" {
		// Try default location.
		vmlinux = filepath.Join(os.Getenv("HOME"), "projects/fuzzing-qemu/linux-stable/vmlinux")
	}
	if _, err := os.Stat(vmlinux); err != nil {
		b.Skipf("vmlinux not found at %v: %v", vmlinux, err)
	}

	// Create native symbolizer.
	target := targets.Get("linux", "amd64")
	target.KernelObject = vmlinux

	symb, err := symbolizer.Make(target, vmlinux)
	if err != nil {
		b.Fatalf("failed to create symbolizer: %v", err)
	}
	defer symb.Close()

	// Gather interesting PCs.
	// We want random PCs across the entire binary to stress the cache and searching.
	pcs := gatherAllPCs(nil, vmlinux)
	if len(pcs) == 0 {
		b.Fatal("no pcs found")
	}

	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		pc := pcs[rng.Intn(len(pcs))]
		_, err := symb.Symbolize(vmlinux, pc)
		if err != nil {
			b.Fatalf("symbolize failed: %v", err)
		}
	}
}

func gatherAllPCs(t *testing.T, bin string) []uint64 {
	cmd := exec.Command("nm", "-n", bin)
	out, err := cmd.Output()
	if err != nil {
		if t != nil {
			t.Fatalf("nm failed: %v", err)
		}
		return nil
	}

	var pcs []uint64
	scanner := bufio.NewScanner(bytes.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()
		parts := strings.Fields(line)
		if len(parts) < 3 {
			continue
		}
		ifParts := parts[1]
		if ifParts == "t" || ifParts == "T" {
			addr, err := strconv.ParseUint(parts[0], 16, 64)
			// Kernel text usually starts high.
			if err == nil && addr > 0xffffffff80000000 {
				pcs = append(pcs, addr)
			}
		}
	}
	return pcs
}
