// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/syzkaller/pkg/ast"
	"github.com/google/syzkaller/pkg/clangtool"
	"github.com/google/syzkaller/pkg/compiler"
	"github.com/google/syzkaller/pkg/ifaceprobe"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/testutil"
)

var (
	flagBin    = flag.String("bin", "", "path to syz-declextract binary to use")
	flagUpdate = flag.Bool("update", false, "update golden files")
)

func TestClangTool(t *testing.T) {
	if *flagBin == "" {
		t.Skipf("syz-declextract path is not specified, run with -bin=syz-declextract flag")
	}
	testEachFile(t, func(t *testing.T, cfg *clangtool.Config, file string) {
		out, err := clangtool.Run(cfg)
		if err != nil {
			t.Fatal(err)
		}
		got, err := json.MarshalIndent(out, "", "\t")
		if err != nil {
			t.Fatal(err)
		}
		compareGoldenData(t, file+".json", got)
	})
}

func TestDeclextract(t *testing.T) {
	testEachFile(t, func(t *testing.T, cfg *clangtool.Config, file string) {
		// Created cache file to avoid running the clang tool.
		goldenFile := file + ".json"
		cacheFile := filepath.Join(cfg.KernelObj, filepath.Base(goldenFile))
		if err := os.Symlink(goldenFile, cacheFile); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(filepath.Join(cfg.KernelSrc, "manual.txt"),
			filepath.Join(cfg.KernelObj, "manual.txt")); err != nil {
			t.Fatal(err)
		}
		cfg.ToolBin = "this-is-not-supposed-to-run"
		probeInfo := new(ifaceprobe.Info)
		probeFile := filepath.Join(cfg.KernelSrc, filepath.Base(file)+".probe")
		if osutil.IsExist(probeFile) {
			var err error
			probeInfo, err = readProbeResult(probeFile)
			if err != nil {
				t.Fatal(err)
			}
		}
		loadProbeInfo := func() (*ifaceprobe.Info, error) {
			return probeInfo, nil
		}
		autoFile := filepath.Join(cfg.KernelObj, filepath.Base(file)+".txt")
		res, err := run(autoFile, loadProbeInfo, cfg)
		if err != nil {
			if *flagUpdate {
				osutil.CopyFile(autoFile, file+".txt")
				osutil.CopyFile(autoFile+".info", file+".info")
			}
			t.Fatal(err)
		}

		// Check that descriptions compile.
		eh, errors := errorHandler()
		full := ast.ParseGlob(filepath.Join(cfg.KernelObj, "*.txt"), eh)
		if full == nil {
			t.Fatalf("failed to parse full descriptions:\n%s", errors)
		}
		constInfo := compiler.ExtractConsts(full, target, eh)
		if constInfo == nil {
			t.Fatalf("failed to compile full descriptions:\n%s", errors)
		}
		// Fabricate consts.
		consts := make(map[string]uint64)
		for _, info := range constInfo {
			for i, c := range info.Consts {
				consts[c.Name] = uint64(i + 1)
			}
		}
		desc := compiler.Compile(full, consts, target, eh)
		if desc == nil {
			t.Fatalf("failed to compile full descriptions:\n%s", errors)
		}

		// Check that generated structs have the same size/align as they had in C.
		// We assume size/align do not depend on const values (which we fabricated).
		for _, typ := range desc.Types {
			info := res.StructInfo[typ.Name()]
			if info == nil {
				continue
			}
			if typ.Size() != uint64(info.Size) || typ.Alignment() != uint64(info.Align) {
				t.Errorf("incorrect generated type %v: size %v/%v align %v/%v",
					typ.Name(), typ.Size(), info.Size, typ.Alignment(), info.Align)
			}
		}

		// TODO: Ensure that none of the syscalls will be disabled by TransitivelyEnabledCalls.

		compareGoldenFile(t, file+".txt", autoFile)
		compareGoldenFile(t, file+".info", autoFile+".info")
	})
}

func testEachFile(t *testing.T, fn func(t *testing.T, cfg *clangtool.Config, file string)) {
	testdata, err := filepath.Abs("testdata")
	if err != nil {
		t.Fatal(err)
	}
	files, err := filepath.Glob(filepath.Join(testdata, "*.c"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("found no source files")
	}
	for _, file := range files {
		t.Run(filepath.Base(file), func(t *testing.T) {
			t.Parallel()
			buildDir := t.TempDir()
			commands := fmt.Sprintf(`[{
					"file": "%s",
					"directory": "%s",
					"command": "clang -c %s -DKBUILD_BASENAME=foo"
				}]`,
				file, buildDir, file)
			dbFile := filepath.Join(buildDir, "compile_commands.json")
			if err := os.WriteFile(dbFile, []byte(commands), 0600); err != nil {
				t.Fatal(err)
			}
			cfg := &clangtool.Config{
				ToolBin:    *flagBin,
				KernelSrc:  testdata,
				KernelObj:  buildDir,
				CacheFile:  filepath.Join(buildDir, filepath.Base(file)+".json"),
				DebugTrace: &testutil.Writer{TB: t},
			}
			fn(t, cfg, file)
		})
	}
}

func compareGoldenFile(t *testing.T, goldenFile, gotFile string) {
	got, err := os.ReadFile(gotFile)
	if err != nil {
		t.Fatal(err)
	}
	compareGoldenData(t, goldenFile, got)
}

func compareGoldenData(t *testing.T, goldenFile string, got []byte) {
	if *flagUpdate {
		if err := os.WriteFile(goldenFile, got, 0644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(goldenFile)
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(got, want); diff != "" {
		t.Fatal(diff)
	}
}
