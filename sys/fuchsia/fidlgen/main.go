// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/ast"
	"github.com/google/syzkaller/pkg/compiler"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/tool"
	"github.com/google/syzkaller/sys/fuchsia/layout"
	"github.com/google/syzkaller/sys/targets"
)

func main() {
	targetArch := os.Getenv("TARGETARCH")
	target := targets.Get(targets.Fuchsia, targetArch)
	if target == nil {
		tool.Failf("unknown TARGETARCH %s", targetArch)
	}
	arch := target.KernelHeaderArch

	sourceDir := os.Getenv("SOURCEDIR")
	if !osutil.IsExist(sourceDir) {
		tool.Failf("cannot find SOURCEDIR %s", sourceDir)
	}

	fidlgenPath := filepath.Join(
		sourceDir,
		"out",
		arch,
		"host_x64",
		"fidlgen_syzkaller",
	)
	if !osutil.IsExist(fidlgenPath) {
		tool.Failf("cannot find fidlgen %s", fidlgenPath)
	}

	var newFiles []string
	for _, fidlLib := range layout.AllFidlLibraries {
		jsonPath := filepath.Join(sourceDir, "out", arch, fidlLib.PathToJSONIr())
		txtPathBase := strings.Replace(strings.Join(fidlLib, "_"), "^fuchsia", "fidl", 1)

		txtPath := fidlgen(
			fidlgenPath,
			jsonPath,
			txtPathBase,
		)

		newFiles = append(newFiles, txtPath)
	}

	var errorPos ast.Pos
	var errorMsg string
	desc := ast.ParseGlob("*.txt", func(pos ast.Pos, msg string) {
		errorPos = pos
		errorMsg = msg
	})
	if desc == nil {
		tool.Failf("parsing failed at %v: %v", errorPos, errorMsg)
	}

	unused := make(map[ast.Node]bool)

	nodes, err := compiler.CollectUnused(desc, target, nil)
	if err != nil {
		tool.Failf("collect unused nodes failed: %v", err)
	}

	for _, n := range nodes {
		unused[n] = true
	}

	pruned := desc.Filter(func(n ast.Node) bool {
		_, ok := unused[n]
		return !ok
	})

	for _, file := range newFiles {
		desc := ast.Format(pruned.Filter(func(n ast.Node) bool {
			pos, _, _ := n.Info()
			return pos.File == file
		}))

		if err := osutil.WriteFile(file, desc); err != nil {
			tool.Fail(err)
		}
	}
}

func fidlgen(fidlgenPath, jsonPath, txtPathBase string) string {
	if !osutil.IsExist(jsonPath) {
		tool.Failf("cannot find %s", jsonPath)
	}

	out, err := osutil.RunCmd(time.Minute, "",
		fidlgenPath,
		"-json", jsonPath,
		"-output-syz", txtPathBase+".syz.txt",
	)
	if len(out) != 0 {
		fmt.Println(string(out))
	}

	if err != nil {
		tool.Failf("fidlgen failed: %v", err)
	}

	return fmt.Sprintf("%s.syz.txt", txtPathBase)
}
