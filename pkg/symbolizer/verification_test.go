// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package symbolizer_test

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"github.com/google/syzkaller/pkg/symbolizer"
	"github.com/google/syzkaller/sys/targets"
)

func TestNativeSymbolizerVerification(t *testing.T) {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Skip("skipping on non-linux/amd64")
	}

	// Find vmlinux.
	vmlinux := os.Getenv("VMLINUX")
	if vmlinux == "" {
		// Try default location.
		vmlinux = filepath.Join(os.Getenv("HOME"), "projects/fuzzing-qemu/linux-stable/vmlinux")
	}
	if _, err := os.Stat(vmlinux); err != nil {
		t.Skipf("vmlinux not found at %v: %v", vmlinux, err)
	}

	// Create native symbolizer.
	target := targets.Get("linux", "amd64")
	target.KernelObject = vmlinux

	symb, err := symbolizer.Make(target)
	if err != nil {
		t.Fatalf("failed to create symbolizer: %v", err)
	}
	defer symb.Close()

	// 1. Gather interesting PCs.
	pcs := gatherPCs(t, vmlinux, 50)
	t.Logf("testing %v PCs...", len(pcs))

	// 2. Run independent verification (llvm-symbolizer).
	refSymbolizerPath, err := exec.LookPath("llvm-symbolizer")
	if err != nil {
		t.Skip("llvm-symbolizer not found")
	}

	refFrames := runLLVMSymbolizer(t, refSymbolizerPath, vmlinux, pcs)

	// 3. Run native symbolizer.
	nativeFrames, err := symb.Symbolize(vmlinux, pcs...)
	if err != nil {
		t.Fatalf("native symbolizer failed: %v", err)
	}

	// 4. Compare.
	if len(nativeFrames) != len(refFrames) {
		t.Fatalf("mismatch in number of frames: native=%v ref=%v", len(nativeFrames), len(refFrames))
	}

	mismatches := 0
	for i, ref := range refFrames {
		native := nativeFrames[i]
		if !compareFrames(t, i, native, ref) {
			mismatches++
			if mismatches > 20 {
				t.Fatalf("too many mismatches")
			}
		}
	}
}

// gatherPCs extracts valid text symbols from the binary.

func gatherPCs(t *testing.T, bin string, count int) []uint64 {
	cmd := exec.Command("nm", "-n", bin)
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("nm failed: %v", err)
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
			if strings.HasPrefix(parts[2], "__") {
				continue
			}
			addr, err := strconv.ParseUint(parts[0], 16, 64)
			if err == nil && addr > 0xffffffff80000000 {
				pcs = append(pcs, addr+4)
				if len(pcs) >= count {
					break
				}
			}
		}
	}
	return pcs
}

func runLLVMSymbolizer(t *testing.T, path, bin string, pcs []uint64) []symbolizer.Frame {
	args := []string{"--obj=" + bin, "--output-style=GNU", "--functions", "--inlining"}
	cmd := exec.Command(path, args...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}

	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}

	go func() {
		for _, pc := range pcs {
			fmt.Fprintf(stdin, "0x%x\n", pc)
		}
		stdin.Close()
	}()

	var frames []symbolizer.Frame
	scanner := bufio.NewScanner(stdout)
	currentFunc := ""
	for scanner.Scan() {
		line := scanner.Text()
		if currentFunc == "" {
			currentFunc = line
			continue
		}
		// Parse frame info.
		// Logic: Find last colon -> Column. Next last -> Line.
		// If only one colon -> File:Line.
		// llvm-symbolizer output style GNU:
		// /path/to/file.c:123:45

		colon1 := strings.LastIndexByte(line, ':')
		if colon1 != -1 {
			// Try to parse number after colon1
			num1, err1 := strconv.Atoi(line[colon1+1:])
			if err1 == nil {
				// We have at least one number.
				// Check for another colon for Line
				colon2 := strings.LastIndexByte(line[:colon1], ':')
				if colon2 != -1 {
					num2, err2 := strconv.Atoi(line[colon2+1 : colon1])
					if err2 == nil {
						// Format: File:Line:Column.
						f := symbolizer.Frame{
							Func:   currentFunc,
							File:   line[:colon2],
							Line:   num2,
							Column: num1,
						}
						frames = append(frames, f)
						currentFunc = ""
						continue
					}
				}
				// Format: File:Line (no column?)
				// or File:Line (and colon1 was splitting file/line)
				// If num1 matches Line convention.
				f := symbolizer.Frame{
					Func: currentFunc,
					File: line[:colon1],
					Line: num1,
				}
				frames = append(frames, f)
				currentFunc = ""
				continue
			}
		}

		// Fallback (?)
		currentFunc = ""
	}
	cmd.Wait()
	return frames
}

func compareFrames(t *testing.T, i int, native, ref symbolizer.Frame) bool {
	nFunc := cleanFunc(native.Func)
	rFunc := cleanFunc(ref.Func)

	funcMatch := (nFunc == rFunc)
	if !funcMatch {
		if strings.Contains(rFunc, nFunc) || strings.Contains(nFunc, rFunc) {
			funcMatch = true
		}
	}

	nFile := filepath.Base(native.File)
	rFile := filepath.Base(ref.File)
	fileMatch := (nFile == rFile)

	if !fileMatch {
		if native.File != "" && (ref.File == "" || ref.File == "??") {
			t.Logf("frame %d: native found file %q while ref didn't. accepting", i, native.File)
			fileMatch = true
		} else if ref.File != "" && native.File == "" {
			fileMatch = false
		}
	}

	if !funcMatch || !fileMatch {
		t.Logf("frame %d mismatch:\n  native: %s %s:%d:%d\n  ref:    %s %s:%d:%d",
			i, native.Func, native.File, native.Line, native.Column, ref.Func, ref.File, ref.Line, ref.Column)
		return false
	}

	lineMismatch := false
	if native.Line != ref.Line && native.Line != 0 && ref.Line != 0 {
		if abs(native.Line-ref.Line) > 1 {
			lineMismatch = true
		}
	}

	if lineMismatch {
		t.Logf("frame %d line mismatch: native=%d ref=%d", i, native.Line, ref.Line)
	}

	// Check Column.
	if native.Column != ref.Column {
		// We tolerate 0 vs non-0 if one symbolizer didn't find it.
		// If native found it (non-0) and ref didn't (0) -> OK.
		if native.Column == 0 && ref.Column != 0 {
			t.Logf("frame %d column missing in native: native=%d ref=%d", i, native.Column, ref.Column)
		} else if native.Column != 0 && ref.Column != 0 && native.Column != ref.Column {
			t.Logf("frame %d column mismatch: native=%d ref=%d", i, native.Column, ref.Column)
		}
	}

	return true
}

func cleanFunc(name string) string {
	if idx := strings.IndexByte(name, '('); idx != -1 {
		name = name[:idx]
	}
	return strings.TrimSpace(name)
}

func abs(a int) int {
	if a < 0 {
		return -a
	}
	return a
}
