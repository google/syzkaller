// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"path/filepath"

	"github.com/google/syzkaller/pkg/compiler"
)

type fuchsia struct{}

func (*fuchsia) prepare(sourcedir string, build bool, arches []string) error {
	if sourcedir == "" {
		return fmt.Errorf("provide path to kernel checkout via -sourcedir flag (or make extract SOURCEDIR)")
	}
	return nil
}

func (*fuchsia) prepareArch(arch *Arch) error {
	return nil
}

func (*fuchsia) processFile(arch *Arch, info *compiler.ConstInfo) (map[string]uint64, map[string]bool, error) {
	dir := arch.sourceDir
	headerArch := arch.target.KernelHeaderArch
	cc := filepath.Join(dir, "buildtools", "linux-x64", "clang", "bin", "clang")
	includeDir := filepath.Join(dir, "out", "build-zircon", "build-"+headerArch, "sysroot", "include")
	args := []string{"-fmessage-length=0", "-I" + includeDir}
	for _, incdir := range info.Incdirs {
		args = append(args, "-I"+filepath.Join(dir, incdir))
	}
	return extract(info, cc, args, "", true)
}
