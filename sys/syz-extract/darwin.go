// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/google/syzkaller/pkg/compiler"
)

type darwin struct{}

func (*darwin) prepare(sourcedir string, build bool, arches []*Arch) error {
	return nil
}

func (*darwin) prepareArch(arch *Arch) error {
	return nil
}

func (*darwin) processFile(arch *Arch, info *compiler.ConstInfo) (map[string]uint64, map[string]bool, error) {
	args := []string{
		"-nostdinc",
		"-DPRIVATE",
		"-DPF",
		"-I", filepath.Join(arch.sourceDir, "bsd"),
		"-I", filepath.Join(arch.sourceDir, "bsd", "sys"),
		"-I", filepath.Join(arch.sourceDir, "osfmk"),
	}
	for _, incdir := range info.Incdirs {
		args = append(args, "-I"+filepath.Join(arch.sourceDir, incdir))
	}
	fmt.Printf("dirs: %v", arch.includeDirs)
	if arch.includeDirs != "" {
		for _, dir := range strings.Split(arch.includeDirs, ",") {
			args = append(args, "-I"+dir)
		}
	}
	// TODO(HerrSpace): investigate use of bsd/kern/syscalls.master and
	// osfmk/mach/mach_traps.h here.
	params := &extractParams{
		AddSource:     "#include <sys/syscall.h>",
		DeclarePrintf: true,
		TargetEndian:  arch.target.HostEndian,
	}
	return extract(info, "clang", args, params)
}
