// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// It may or may not work on other OSes.
// If you test on another OS and it works, enable it.
// +build linux

package cover

import (
	"bytes"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/symbolizer"
	_ "github.com/google/syzkaller/sys"
	"github.com/google/syzkaller/sys/targets"
)

type Test struct {
	Name   string
	CFlags []string
	Progs  []Prog
	Result string
}

func TestReportGenerator(t *testing.T) {
	tests := []Test{
		{
			Name:   "no-coverage",
			CFlags: []string{"-g"},
			Result: `.* doesn't contain coverage callbacks '.*__sanitizer_cov_trace_pc>\]' \(set CONFIG_KCOV=y\)`,
		},
		{
			Name:   "no-debug-info",
			CFlags: []string{"-fsanitize-coverage=trace-pc"},
			Result: `.* doesn't have debug info \(set CONFIG_DEBUG_INFO=y\)`,
		},
		{
			Name:   "no-pcs",
			CFlags: []string{"-fsanitize-coverage=trace-pc", "-g"},
			Result: `no coverage collected so far`,
		},
		{
			Name:   "bad-pcs",
			CFlags: []string{"-fsanitize-coverage=trace-pc", "-g"},
			Progs:  []Prog{{Data: "data", PCs: []uint64{0x1, 0x2}}},
			Result: `coverage \(2\) doesn't match coverage callbacks`,
		},
		{
			Name:   "good",
			CFlags: []string{"-fsanitize-coverage=trace-pc", "-g"},
		},
	}
	t.Parallel()
	for os, arches := range targets.List {
		if os == "test" {
			continue
		}
		for _, target := range arches {
			target := targets.Get(target.OS, target.Arch)
			if target.BuildOS != runtime.GOOS {
				continue
			}
			t.Run(target.OS+"-"+target.Arch, func(t *testing.T) {
				t.Parallel()
				if target.BrokenCompiler != "" {
					t.Skip("skipping the test due to broken cross-compiler:\n" + target.BrokenCompiler)
				}
				for _, test := range tests {
					test := test
					t.Run(test.Name, func(t *testing.T) {
						t.Parallel()
						testReportGenerator(t, target, test)
					})
				}
			})
		}
	}
}

func testReportGenerator(t *testing.T, target *targets.Target, test Test) {
	rep, err := generateReport(t, target, test)
	if err != nil {
		if test.Result == "" {
			t.Fatalf("expected no error, but got:\n%v", err)
		}
		if !regexp.MustCompile(test.Result).MatchString(err.Error()) {
			t.Fatalf("expected error %q, but got:\n%v", test.Result, err)
		}
		return
	}
	if test.Result != "" {
		t.Fatalf("got no error, but expected %q", test.Result)
	}
	_ = rep
}

func buildTestBinary(t *testing.T, target *targets.Target, test Test, dir string) string {
	kcovSrc := filepath.Join(dir, "kcov.c")
	kcovObj := filepath.Join(dir, "kcov.o")
	if err := osutil.WriteFile(kcovSrc, []byte(`
#include <stdio.h>
void __sanitizer_cov_trace_pc() { printf("%llu", (long long)__builtin_return_address(0)); }
`)); err != nil {
		t.Fatal(err)
	}
	kcovFlags := append([]string{"-c", "-w", "-x", "c", "-o", kcovObj, kcovSrc}, target.CFlags...)
	src := filepath.Join(dir, "main.c")
	bin := filepath.Join(dir, "bin")
	if err := osutil.WriteFile(src, []byte(`int main() {}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := osutil.RunCmd(time.Hour, "", target.CCompiler, kcovFlags...); err != nil {
		t.Fatal(err)
	}
	flags := append(append([]string{"-w", "-o", bin, src, kcovObj}, target.CFlags...), test.CFlags...)
	if _, err := osutil.RunCmd(time.Hour, "", target.CCompiler, flags...); err != nil {
		errText := err.Error()
		errText = strings.ReplaceAll(errText, "‘", "'")
		errText = strings.ReplaceAll(errText, "’", "'")
		if strings.Contains(errText, "error: unrecognized command line option '-fsanitize-coverage=trace-pc'") &&
			(os.Getenv("SYZ_BIG_ENV") == "" || target.OS == "akaros") {
			t.Skip("skipping test, -fsanitize-coverage=trace-pc is not supported")
		}
		t.Fatal(err)
	}
	return bin
}

func generateReport(t *testing.T, target *targets.Target, test Test) ([]byte, error) {
	dir, err := ioutil.TempDir("", "syz-cover-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	bin := buildTestBinary(t, target, test, dir)
	rg, err := MakeReportGenerator(target, bin, dir, dir)
	if err != nil {
		return nil, err
	}
	if test.Result == "" {
		var pcs []uint64
		if output, err := osutil.RunCmd(time.Minute, "", bin); err == nil {
			pc, err := strconv.ParseUint(string(output), 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			pcs = append(pcs, PreviousInstructionPC(target, pc))
			t.Logf("using exact coverage PC 0x%x", pcs[0])
		} else if target.OS == runtime.GOOS && (target.Arch == runtime.GOARCH || target.VMArch == runtime.GOARCH) {
			t.Fatal(err)
		} else {
			symb := symbolizer.NewSymbolizer(target)
			text, err := symb.ReadTextSymbols(bin)
			if err != nil {
				t.Fatal(err)
			}
			if nmain := len(text["main"]); nmain != 1 {
				t.Fatalf("got %v main symbols", nmain)
			}
			main := text["main"][0]
			for off := 0; off < main.Size; off++ {
				pcs = append(pcs, main.Addr+uint64(off))
			}
			t.Logf("using inexact coverage range 0x%x-0x%x", main.Addr, main.Addr+uint64(main.Size))
		}
		test.Progs = append(test.Progs, Prog{Data: "main", PCs: pcs})
	}
	out := new(bytes.Buffer)
	if err := rg.Do(out, test.Progs); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}
