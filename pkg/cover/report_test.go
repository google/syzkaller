// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// It may or may not work on other OSes.
// If you test on another OS and it works, enable it.
// +build linux

package cover

import (
	"bytes"
	"encoding/csv"
	"io/ioutil"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/cover/backend"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/symbolizer"
	_ "github.com/google/syzkaller/sys"
	"github.com/google/syzkaller/sys/targets"
)

type Test struct {
	Name     string
	CFlags   []string
	Progs    []Prog
	AddCover bool
	Result   string
	Supports func(target *targets.Target) bool
}

func TestReportGenerator(t *testing.T) {
	tests := []Test{
		{
			Name:     "no-coverage",
			CFlags:   []string{"-g"},
			AddCover: true,
			Result:   `.* doesn't contain coverage callbacks \(set CONFIG_KCOV=y\)`,
		},
		{
			Name:     "no-debug-info",
			CFlags:   []string{"-fsanitize-coverage=trace-pc"},
			AddCover: true,
			Result:   `failed to parse DWARF.*\(set CONFIG_DEBUG_INFO=y\?\)`,
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
			Result: `coverage doesn't match any coverage callbacks`,
		},
		{
			Name:     "good",
			AddCover: true,
			CFlags:   []string{"-fsanitize-coverage=trace-pc", "-g"},
		},
		{
			Name:     "good-pie",
			AddCover: true,
			CFlags: []string{"-fsanitize-coverage=trace-pc", "-g", "-fpie", "-pie",
				"-Wl,--section-start=.text=0x33300000"},
			Supports: func(target *targets.Target) bool {
				return target.OS == targets.Fuchsia ||
					// Fails with "relocation truncated to fit: R_AARCH64_CALL26 against symbol `memcpy'".
					target.OS == targets.Linux && target.Arch != targets.ARM64
			},
		},
		{
			Name:     "good-pie-relocs",
			AddCover: true,
			// This produces a binary that resembles CONFIG_RANDOMIZE_BASE=y.
			// Symbols and .text section has addresses around 0x33300000,
			// but debug info has all PC ranges around 0 address.
			CFlags: []string{"-fsanitize-coverage=trace-pc", "-g", "-fpie", "-pie",
				"-Wl,--section-start=.text=0x33300000,--emit-relocs"},
			Supports: func(target *targets.Target) bool {
				return target.OS == targets.Fuchsia ||
					target.OS == targets.Linux && target.Arch != targets.ARM64 &&
						target.Arch != targets.ARM && target.Arch != targets.I386
			},
		},
	}
	t.Parallel()
	for os, arches := range targets.List {
		if os == targets.TestOS {
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
						if test.Supports != nil && !test.Supports(target) {
							t.Skip("unsupported target")
						}
						t.Parallel()
						testReportGenerator(t, target, test)
					})
				}
			})
		}
	}
}

func testReportGenerator(t *testing.T, target *targets.Target, test Test) {
	rep, csv, err := generateReport(t, target, test)
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
	checkCSVReport(t, csv)
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
	bin := filepath.Join(dir, target.KernelObject)
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
			(os.Getenv("SYZ_BIG_ENV") == "" || target.OS == targets.Akaros) {
			t.Skip("skipping test, -fsanitize-coverage=trace-pc is not supported")
		}
		t.Fatal(err)
	}
	return bin
}

func generateReport(t *testing.T, target *targets.Target, test Test) ([]byte, []byte, error) {
	dir, err := ioutil.TempDir("", "syz-cover-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	bin := buildTestBinary(t, target, test, dir)
	subsystem := []Subsystem{
		{
			Name: "sound",
			Paths: []string{
				"sound",
				"techpack/audio",
			},
		},
	}

	rg, err := MakeReportGenerator(target, "", dir, dir, dir, subsystem)
	if err != nil {
		return nil, nil, err
	}
	if test.AddCover {
		var pcs []uint64
		if output, err := osutil.RunCmd(time.Minute, "", bin); err == nil {
			pc, err := strconv.ParseUint(string(output), 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			pcs = append(pcs, backend.PreviousInstructionPC(target, pc))
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
	html := new(bytes.Buffer)
	if err := rg.DoHTML(html, test.Progs); err != nil {
		return nil, nil, err
	}
	htmlTable := new(bytes.Buffer)
	if err := rg.DoHTMLTable(htmlTable, test.Progs); err != nil {
		return nil, nil, err
	}
	_ = htmlTable
	csv := new(bytes.Buffer)
	if err := rg.DoCSV(csv, test.Progs); err != nil {
		return nil, nil, err
	}
	csvFiles := new(bytes.Buffer)
	if err := rg.DoCSVFiles(csvFiles, test.Progs); err != nil {
		return nil, nil, err
	}
	_ = csvFiles

	return html.Bytes(), csv.Bytes(), nil
}

func checkCSVReport(t *testing.T, CSVReport []byte) {
	csvReader := csv.NewReader(bytes.NewBuffer(CSVReport))
	lines, err := csvReader.ReadAll()
	if err != nil {
		t.Fatal(err)
	}

	if !reflect.DeepEqual(lines[0], csvHeader) {
		t.Fatalf("heading line in CSV doesn't match %v", lines[0])
	}

	foundMain := false
	for _, line := range lines {
		if line[1] == "main" {
			foundMain = true
			if line[2] != "1" && line[3] != "1" {
				t.Fatalf("function coverage percentage doesn't match %v vs. %v", line[2], "100")
			}
		}
	}
	if !foundMain {
		t.Fatalf("no main in the CSV report")
	}
}
