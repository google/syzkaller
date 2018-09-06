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
	"github.com/google/syzkaller/sys/targets"
)

var zirconLibs = []string{
	"fuchsia-mem",
	"fuchsia-cobalt",
	"fuchsia-process",
	"fuchsia-io",
}

func main() {
	targetArch := os.Getenv("TARGETARCH")
	target := targets.Get("fuchsia", targetArch)
	if target == nil {
		failf("unknown TARGETARCH %s", targetArch)
	}
	arch := target.KernelHeaderArch

	sourceDir := os.Getenv("SOURCEDIR")
	if !osutil.IsExist(sourceDir) {
		failf("cannot find SOURCEDIR %s", sourceDir)
	}

	fidlgenPath := filepath.Join(
		sourceDir,
		"out",
		arch,
		fmt.Sprintf("host_%s", arch),
		"fidlgen",
	)
	if !osutil.IsExist(fidlgenPath) {
		failf("cannot find fidlgen %s", fidlgenPath)
	}

	var newFiles []string

	for _, lib := range zirconLibs {
		jsonPath := filepath.Join(
			sourceDir,
			"out",
			arch,
			"fidling/gen/zircon/public/fidl",
			lib,
			fmt.Sprintf("%s.fidl.json", lib),
		)

		if !osutil.IsExist(jsonPath) {
			failf("cannot find %s", jsonPath)
		}

		txtPath := strings.Replace(lib, "fuchsia-", "fidl_", 1)
		_, err := osutil.RunCmd(time.Minute, "",
			fidlgenPath,
			"-generators", "syzkaller",
			"-json", jsonPath,
			"-output-base", txtPath,
			"-include-base", txtPath,
		)

		if err != nil {
			failf("fidlgen failed: %v", err)
		}

		newFiles = append(newFiles, fmt.Sprintf("%s.txt", txtPath))
	}

	var errorPos ast.Pos
	var errorMsg string
	desc := ast.ParseGlob("*.txt", func(pos ast.Pos, msg string) {
		errorPos = pos
		errorMsg = msg
	})
	if desc == nil {
		failf("parsing failed at %v: %v", errorPos, errorMsg)
	}

	unused := make(map[ast.Node]bool)
	for _, n := range compiler.CollectUnused(desc, target) {
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
			failf("%v", err)
		}
	}
}

func failf(msg string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, msg+"\n", args...)
	os.Exit(1)
}
