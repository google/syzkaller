// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/google/syzkaller/pkg/compiler"
)

type freebsd struct{}

func (*freebsd) prepare(sourcedir string, build bool, arches []string) error {
	if sourcedir == "" {
		return fmt.Errorf("provide path to kernel checkout via -sourcedir flag (or make extract SOURCEDIR)")
	}
	if !build {
		return fmt.Errorf("freebsd requires -build flag")
	}
	return nil
}

func (*freebsd) prepareArch(arch *Arch) error {
	if err := os.Symlink(filepath.Join(arch.sourceDir, "sys", "amd64", "include"),
		filepath.Join(arch.buildDir, "machine")); err != nil {
		return fmt.Errorf("failed to create link: %v", err)
	}
	if err := os.Symlink(filepath.Join(arch.sourceDir, "sys", "x86", "include"),
		filepath.Join(arch.buildDir, "x86")); err != nil {
		return fmt.Errorf("failed to create link: %v", err)
	}
	return nil
}

func (*freebsd) processFile(arch *Arch, info *compiler.ConstInfo) (map[string]uint64, map[string]bool, error) {
	args := []string{
		"-fmessage-length=0",
		"-nostdinc",
		"-D_KERNEL",
		"-D__BSD_VISIBLE=1",
		"-I", filepath.Join(arch.sourceDir, "sys"),
		"-I", filepath.Join(arch.sourceDir, "sys", "sys"),
		"-I", filepath.Join(arch.sourceDir, "sys", "amd64"),
		"-I", arch.buildDir,
	}
	for _, incdir := range info.Incdirs {
		args = append(args, "-I"+filepath.Join(arch.sourceDir, incdir))
	}
	// Syscall consts on freebsd have weird prefixes sometimes,
	// try to extract consts with these prefixes as well.
	compatNames := make(map[string][]string)
	for _, val := range info.Consts {
		const SYS = "SYS_"
		if strings.HasPrefix(val, SYS) {
			for _, prefix := range []string{"__", "freebsd11_", "freebsd10_", "freebsd7_"} {
				compat := SYS + prefix + val[len(SYS):]
				compatNames[val] = append(compatNames[val], compat)
				info.Consts = append(info.Consts, compat)
			}
		} else {
			compat := "LINUX_" + val
			compatNames[val] = append(compatNames[val], compat)
			info.Consts = append(info.Consts, compat)
		}
	}
	res, undeclared, err := extract(info, "gcc", args, "#include <sys/syscall.h>", true)
	for orig, compats := range compatNames {
		for _, compat := range compats {
			if undeclared[orig] && !undeclared[compat] {
				res[orig] = res[compat]
				delete(res, compat)
				delete(undeclared, orig)
			}
			delete(undeclared, compat)
		}
	}
	return res, undeclared, err
}
