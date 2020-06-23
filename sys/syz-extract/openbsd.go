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

type openbsd struct{}

func (*openbsd) prepare(sourcedir string, build bool, arches []*Arch) error {
	if sourcedir == "" {
		return fmt.Errorf("provide path to kernel checkout via -sourcedir flag (or make extract SOURCEDIR)")
	}
	if !build {
		return fmt.Errorf("openbsd requires -build flag")
	}
	return nil
}

func (*openbsd) prepareArch(arch *Arch) error {
	if err := os.Symlink(filepath.Join(arch.sourceDir, "sys", "arch", "amd64", "include"),
		filepath.Join(arch.buildDir, "amd64")); err != nil {
		return fmt.Errorf("failed to create link: %v", err)
	}
	if err := os.Symlink(filepath.Join(arch.sourceDir, "sys", "arch", "amd64", "include"),
		filepath.Join(arch.buildDir, "machine")); err != nil {
		return fmt.Errorf("failed to create link: %v", err)
	}
	return nil
}

func (*openbsd) processFile(arch *Arch, info *compiler.ConstInfo) (map[string]uint64, map[string]bool, error) {
	args := []string{
		"-fmessage-length=0",
		"-nostdinc",
		"-D_KERNEL",
		"-D__BSD_VISIBLE=1",
		"-I", filepath.Join(arch.sourceDir, "sys"),
		"-I", filepath.Join(arch.sourceDir, "sys", "sys"),
		"-I", filepath.Join(arch.sourceDir, "sys", "arch", "amd64"),
		"-I", filepath.Join(arch.sourceDir, "common", "include"),
		"-I", filepath.Join(arch.sourceDir, "sys", "compat", "linux", "common"),
		"-I", arch.buildDir,
	}
	for _, incdir := range info.Incdirs {
		args = append(args, "-I"+filepath.Join(arch.sourceDir, incdir))
	}
	if arch.includeDirs != "" {
		for _, dir := range strings.Split(arch.includeDirs, ",") {
			args = append(args, "-I"+dir)
		}
	}
	// Some syscalls on OpenBSD are prefixed with `SYS___' as opposed of the
	// more common `SYS_' prefix.
	syscallsQuirks := map[string]bool{
		"SYS_get_tcb":      true,
		"SYS_getcwd":       true,
		"SYS_realpath":     true,
		"SYS_semctl":       true,
		"SYS_set_tcb":      true,
		"SYS_syscall":      true,
		"SYS_tfork":        true,
		"SYS_threxit":      true,
		"SYS_thrsigdivert": true,
		"SYS_thrsleep":     true,
		"SYS_thrwakeup":    true,
		"SYS_tmpfd":        true,
	}
	compatNames := make(map[string][]string)
	for _, val := range info.Consts {
		if _, ok := syscallsQuirks[val]; ok {
			compat := "SYS___" + val[len("SYS_"):]
			compatNames[val] = append(compatNames[val], compat)
			info.Consts = append(info.Consts, compat)
		}
	}
	params := &extractParams{
		AddSource:    "#include <sys/syscall.h>",
		TargetEndian: arch.target.HostEndian,
	}
	res, undeclared, err := extract(info, "cc", args, params)
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
