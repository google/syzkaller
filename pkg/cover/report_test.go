// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// It may or may not work on other OSes.
// If you test on another OS and it works, enable it.
//go:build linux
// +build linux

package cover

import (
	"bytes"
	"encoding/csv"
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
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/symbolizer"
	_ "github.com/google/syzkaller/sys"
	"github.com/google/syzkaller/sys/targets"
)

type Test struct {
	Name      string
	CFlags    []string
	LDFlags   []string
	Progs     []Prog
	DebugInfo bool
	AddCover  bool
	Result    string
	Supports  func(target *targets.Target) bool
}

func TestReportGenerator(t *testing.T) {
	tests := []Test{
		{
			Name:      "no-coverage",
			DebugInfo: true,
			AddCover:  true,
			Result:    `.* doesn't contain coverage callbacks \(set CONFIG_KCOV=y on linux\)`,
		},
		{
			Name:     "no-debug-info",
			CFlags:   []string{"-fsanitize-coverage=trace-pc"},
			AddCover: true,
			Result:   `failed to parse DWARF.*\(set CONFIG_DEBUG_INFO=y on linux\)`,
		},
		{
			Name:      "no-pcs",
			CFlags:    []string{"-fsanitize-coverage=trace-pc"},
			DebugInfo: true,
			Result:    `no coverage collected so far`,
		},
		{
			Name:      "bad-pcs",
			CFlags:    []string{"-fsanitize-coverage=trace-pc"},
			DebugInfo: true,
			Progs:     []Prog{{Data: "data", PCs: []uint64{0x1, 0x2}}},
			Result:    `coverage doesn't match any coverage callbacks`,
		},
		{
			Name:      "good",
			AddCover:  true,
			CFlags:    []string{"-fsanitize-coverage=trace-pc"},
			DebugInfo: true,
		},
		{
			Name:      "good-pie",
			AddCover:  true,
			CFlags:    []string{"-fsanitize-coverage=trace-pc", "-fpie"},
			LDFlags:   []string{"-pie", "-Wl,--section-start=.text=0x33300000"},
			DebugInfo: true,
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
			CFlags:    []string{"-fsanitize-coverage=trace-pc", "-fpie"},
			LDFlags:   []string{"-pie", "-Wl,--section-start=.text=0x33300000,--emit-relocs"},
			DebugInfo: true,
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

const kcovCode = `
#ifdef ASLR_BASE
#define _GNU_SOURCE
#endif

#include <stdio.h>

#ifdef ASLR_BASE
#include <dlfcn.h>
#include <link.h>
#include <stddef.h>

void* aslr_base() {
       struct link_map* map = NULL;
       void* handle = dlopen(NULL, RTLD_LAZY | RTLD_NOLOAD);
       if (handle != NULL) {
              dlinfo(handle, RTLD_DI_LINKMAP, &map);
              dlclose(handle);
       }
       return map ? map->l_addr : NULL;
}
#else
void* aslr_base() { return NULL; }
#endif

void __sanitizer_cov_trace_pc() { printf("%llu", (long long)(__builtin_return_address(0) - aslr_base())); }
`

func buildTestBinary(t *testing.T, target *targets.Target, test Test, dir string) string {
	kcovSrc := filepath.Join(dir, "kcov.c")
	kcovObj := filepath.Join(dir, "kcov.o")
	if err := osutil.WriteFile(kcovSrc, []byte(kcovCode)); err != nil {
		t.Fatal(err)
	}

	aslrDefine := "-DNO_ASLR_BASE"
	if target.OS == targets.Linux || target.OS == targets.OpenBSD ||
		target.OS == targets.FreeBSD || target.OS == targets.NetBSD {
		aslrDefine = "-DASLR_BASE"
	}
	aslrExtraLibs := []string{}
	if target.OS == targets.Linux {
		aslrExtraLibs = []string{"-ldl"}
	}

	kcovFlags := append([]string{"-c", "-fpie", "-w", "-x", "c", "-o", kcovObj, kcovSrc, aslrDefine}, target.CFlags...)
	src := filepath.Join(dir, "main.c")
	obj := filepath.Join(dir, "main.o")
	bin := filepath.Join(dir, target.KernelObject)
	if err := osutil.WriteFile(src, []byte(`int main() {}`)); err != nil {
		t.Fatal(err)
	}
	if _, err := osutil.RunCmd(time.Hour, "", target.CCompiler, kcovFlags...); err != nil {
		t.Fatal(err)
	}

	// We used to compile and link with a single compiler invocation,
	// but clang has a bug that it tries to link in ubsan runtime when
	// -fsanitize-coverage=trace-pc is provided during linking and
	// ubsan runtime is missing for arm/arm64/riscv arches in the llvm packages.
	// So we first compile with -fsanitize-coverage and then link w/o it.
	cflags := append(append([]string{"-w", "-c", "-o", obj, src}, target.CFlags...), test.CFlags...)
	if test.DebugInfo {
		// TODO: pkg/cover doesn't support DWARF5 yet, which is the default in Clang.
		cflags = append([]string{"-g", "-gdwarf-4"}, cflags...)
	}
	if _, err := osutil.RunCmd(time.Hour, "", target.CCompiler, cflags...); err != nil {
		errText := err.Error()
		errText = strings.ReplaceAll(errText, "‘", "'")
		errText = strings.ReplaceAll(errText, "’", "'")
		if strings.Contains(errText, "error: unrecognized command line option '-fsanitize-coverage=trace-pc'") &&
			(os.Getenv("SYZ_BIG_ENV") == "" || target.OS == targets.Akaros) {
			t.Skip("skipping test, -fsanitize-coverage=trace-pc is not supported")
		}
		t.Fatal(err)
	}

	ldflags := append(append(append([]string{"-o", bin, obj, kcovObj}, aslrExtraLibs...),
		target.CFlags...), test.LDFlags...)
	staticIdx, pieIdx := -1, -1
	for i, arg := range ldflags {
		switch arg {
		case "-static":
			staticIdx = i
		case "-pie":
			pieIdx = i
		}
	}
	if target.OS == targets.Fuchsia && pieIdx != -1 {
		// Fuchsia toolchain fails when given -pie:
		// clang-12: error: argument unused during compilation: '-pie'
		ldflags[pieIdx] = ldflags[len(ldflags)-1]
		ldflags = ldflags[:len(ldflags)-1]
	} else if pieIdx != -1 && staticIdx != -1 {
		// -static and -pie are incompatible during linking.
		ldflags[staticIdx] = ldflags[len(ldflags)-1]
		ldflags = ldflags[:len(ldflags)-1]
	}
	if _, err := osutil.RunCmd(time.Hour, "", target.CCompiler, ldflags...); err != nil {
		// Arm linker in the big-env image has a bug when linking a clang-produced files.
		if regexp.MustCompile(`arm-linux-gnueabi.* assertion fail`).MatchString(err.Error()) {
			t.Skipf("skipping test, broken arm linker (%v)", err)
		}
		t.Fatal(err)
	}
	return bin
}

func generateReport(t *testing.T, target *targets.Target, test Test) ([]byte, []byte, error) {
	dir := t.TempDir()
	bin := buildTestBinary(t, target, test, dir)
	subsystem := []mgrconfig.Subsystem{
		{
			Name: "sound",
			Paths: []string{
				"sound",
				"techpack/audio",
			},
		},
	}

	// Deep copy, as we are going to modify progs. Our test generate multiple reports from the same
	// test object in parallel. Without copying we have a datarace here.
	progs := []Prog{}
	for _, p := range test.Progs {
		progs = append(progs, Prog{Sig: p.Sig, Data: p.Data, PCs: append([]uint64{}, p.PCs...)})
	}

	rg, err := MakeReportGenerator(target, "", dir, dir, dir, subsystem, nil, nil, false)
	if err != nil {
		return nil, nil, err
	}
	if test.AddCover {
		var pcs []uint64
		// Sanitizers crash when installing signal handlers with static libc.
		const sanitizerOptions = "handle_segv=0:handle_sigbus=0:handle_sigfpe=0"
		cmd := osutil.Command(bin)
		cmd.Env = append([]string{
			"UBSAN_OPTIONS=" + sanitizerOptions,
			"ASAN_OPTIONS=" + sanitizerOptions,
		}, os.Environ()...)
		if output, err := osutil.Run(time.Minute, cmd); err == nil {
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
		progs = append(progs, Prog{Data: "main", PCs: pcs})
	}
	html := new(bytes.Buffer)
	if err := rg.DoHTML(html, progs, nil); err != nil {
		return nil, nil, err
	}
	htmlTable := new(bytes.Buffer)
	if err := rg.DoHTMLTable(htmlTable, progs, nil); err != nil {
		return nil, nil, err
	}
	_ = htmlTable
	csv := new(bytes.Buffer)
	if err := rg.DoCSV(csv, progs, nil); err != nil {
		return nil, nil, err
	}
	csvFiles := new(bytes.Buffer)
	if err := rg.DoCSVFiles(csvFiles, progs, nil); err != nil {
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
		if line[2] == "main" {
			foundMain = true
			if line[3] != "1" && line[4] != "1" {
				t.Fatalf("function coverage percentage doesn't match %v vs. %v", line[3], "100")
			}
		}
	}
	if !foundMain {
		t.Fatalf("no main in the CSV report")
	}
}
