// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/google/syzkaller/pkg/compiler"
)

type akaros struct{}

func (*akaros) prepare(sourcedir string, build bool, arches []string) error {
	if sourcedir == "" {
		return fmt.Errorf("provide path to kernel checkout via -sourcedir flag (or make extract SOURCEDIR)")
	}
	return nil
}

func (*akaros) prepareArch(arch *Arch) error {
	return nil
}

func (*akaros) processFile(arch *Arch, info *compiler.ConstInfo) (map[string]uint64, map[string]bool, error) {
	dir := arch.sourceDir
	args := []string{
		"-fmessage-length=0",
		"-D__KERNEL__",
		"-DROS_KERNEL",
		"-I", filepath.Join(dir, "kern", "include"),
		"-I", filepath.Join(dir, "user", "parlib", "include"),
	}
	for _, incdir := range info.Incdirs {
		args = append(args, "-I"+filepath.Join(dir, incdir))
	}
	if arch.includeDirs != "" {
		for _, dir := range strings.Split(arch.includeDirs, ",") {
			args = append(args, "-I"+dir)
		}
	}
	params := &extractParams{
		DeclarePrintf: true,
	}
	return extract(info, "gcc", args, params)
}
