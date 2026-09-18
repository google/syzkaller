// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/syzkaller/pkg/ast"
	"github.com/google/syzkaller/pkg/clangtool"
	"github.com/google/syzkaller/pkg/clangtool/tooltest"
	"github.com/google/syzkaller/pkg/compiler"
	"github.com/google/syzkaller/pkg/declextract"
	"github.com/google/syzkaller/pkg/ifaceprobe"
	"github.com/google/syzkaller/pkg/osutil"
	clangtoolimpl "github.com/google/syzkaller/tools/clang/declextract"
)

func TestClangTool(t *testing.T) {
	tooltest.TestClangTool[declextract.Output](t, clangtoolimpl.Tool)
}

func TestOverlayExtract(t *testing.T) {
	dir := t.TempDir()
	manualContent := `meta arches["amd64"]
meta overlay["manual_auto.txt"]

foo(a ptr[in, struct_a], b ptr[in, struct_b])

override struct_b {
	x	int32
	y	int32
}
`
	if err := osutil.WriteFile(filepath.Join(dir, "manual.txt"), []byte(manualContent)); err != nil {
		t.Fatal(err)
	}
	out := &declextract.Output{
		Structs: []*declextract.Struct{
			{
				Name:     "struct_a",
				ByteSize: 8,
				Align:    8,
				Fields: []*declextract.Field{
					{
						Name:      "sub",
						CountedBy: -1,
						Type:      &declextract.Type{Struct: "struct_sub"},
					},
				},
			},
			{
				Name:     "struct_sub",
				ByteSize: 8,
				Align:    8,
				Fields: []*declextract.Field{
					{
						Name:      "val",
						CountedBy: -1,
						Type:      &declextract.Type{Int: &declextract.IntType{ByteSize: 8}},
					},
				},
			},
			{
				Name:     "struct_b",
				ByteSize: 8,
				Align:    4,
				Fields: []*declextract.Field{
					{
						Name:      "x",
						CountedBy: -1,
						Type:      &declextract.Type{Int: &declextract.IntType{ByteSize: 4}},
					},
					{
						Name:      "y",
						CountedBy: -1,
						Type:      &declextract.Type{Int: &declextract.IntType{ByteSize: 4}},
					},
				},
			},
			{
				Name:     "struct_unused",
				ByteSize: 4,
				Align:    4,
				Fields: []*declextract.Field{
					{
						Name:      "z",
						CountedBy: -1,
						Type:      &declextract.Type{Int: &declextract.IntType{ByteSize: 4}},
					},
				},
			},
		},
	}
	autoFile := filepath.Join(dir, "auto.txt")
	overlays, err := discoverOverlays(dir, autoFile)
	if err != nil {
		t.Fatal(err)
	}
	if len(overlays) != 1 {
		t.Fatalf("expected 1 overlay, got %d", len(overlays))
	}
	spec := overlays[0]
	res, err := declextract.RunOverlay(out, new(ifaceprobe.Info), spec.roots,
		spec.excludeStructs, spec.excludeEnums, spec.arches, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := osutil.WriteFile(spec.overlayFile, res.Descriptions); err != nil {
		t.Fatal(err)
	}
	eh, errors := errorHandler()
	desc := ast.ParseGlob(filepath.Join(dir, "*.txt"), eh)
	if desc == nil {
		t.Fatalf("failed to parse descriptions:\n%s", errors.Bytes())
	}
	unusedNodes, err := compiler.CollectUnused(desc.Clone(), target, eh)
	if err != nil {
		t.Fatalf("failed to typecheck descriptions: %v\n%s", err, errors.Bytes())
	}
	removeUnusedNodes(desc, unusedNodes)
	unusedConsts, err := compiler.CollectUnusedConsts(desc.Clone(), target, res.IncludeUse, eh)
	if err != nil {
		t.Fatalf("failed to typecheck descriptions: %v\n%s", err, errors.Bytes())
	}
	removeUnusedNodes(desc, unusedConsts)
	fileDesc := filterFile(desc, spec.overlayFile)
	formatted := string(ast.Format(ast.Parse(ast.Format(fileDesc), spec.overlayFile, nil)))
	if err := osutil.WriteFile(spec.overlayFile, []byte(formatted)); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"struct_a {", "struct_sub {", "struct_b {"} {
		if !strings.Contains(formatted, want) {
			t.Errorf("overlay file missing %q:\n%s", want, formatted)
		}
	}
	if strings.Contains(formatted, "struct_unused") {
		t.Errorf("overlay file should not contain struct_unused:\n%s", formatted)
	}
}

func TestDeclextract(t *testing.T) {
	tooltest.ForEachTestFile(t, clangtoolimpl.Tool, func(t *testing.T, cfg *clangtool.Config, file string) {
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
		cfg.Tool = "this-is-not-supposed-to-run"
		probeInfo := new(ifaceprobe.Info)
		probeFile := filepath.Join(cfg.KernelSrc, filepath.Base(file)+".probe")
		if osutil.IsExist(probeFile) {
			var err error
			probeInfo, err = readProbeResult(probeFile)
			if err != nil {
				t.Fatal(err)
			}
		}
		coverFile := filepath.Join(cfg.KernelSrc, filepath.Base(file)+".cover")
		if !osutil.IsExist(coverFile) {
			coverFile = ""
		}
		autoFile := filepath.Join(cfg.KernelObj, filepath.Base(file)+".txt")
		runcfg := &config{
			autoFile:  autoFile,
			coverFile: coverFile,
			loadProbeInfo: func() (*ifaceprobe.Info, error) {
				return probeInfo, nil
			},
			Config: cfg,
		}
		res, err := run(runcfg)
		if err != nil {
			if *tooltest.FlagUpdate {
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

		tooltest.CompareGoldenFile(t, file+".txt", autoFile)
		tooltest.CompareGoldenFile(t, file+".info", autoFile+".info")
	})
}
