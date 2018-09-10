// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package build

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strconv"
	"time"

	"github.com/google/syzkaller/pkg/osutil"
)

type openbsd struct{}

func (ctx openbsd) build(targetArch, vmType, kernelDir, outputDir, compiler, userspaceDir,
	cmdlineFile, sysctlFile string, config []byte) error {
	const kernelName = "SYZKALLER"
	confDir := fmt.Sprintf("%v/sys/arch/%v/conf", kernelDir, targetArch)
	compileDir := fmt.Sprintf("%v/sys/arch/%v/compile/%v", kernelDir, targetArch, kernelName)

	if err := ctx.configure(confDir, compileDir, kernelName); err != nil {
		return err
	}

	if err := ctx.make(compileDir, "all"); err != nil {
		return err
	}

	for src, dst := range map[string]string{
		"obj/bsd":     "kernel",
		"obj/bsd.gdb": "obj/bsd.gdb",
	} {
		fullSrc := filepath.Join(compileDir, src)
		fullDst := filepath.Join(outputDir, dst)
		if err := osutil.CopyFile(fullSrc, fullDst); err != nil {
			return fmt.Errorf("failed to copy %v -> %v: %v", fullSrc, fullDst, err)
		}
	}

	return nil
}

func (ctx openbsd) clean(kernelDir string) error {
	return ctx.make(kernelDir, "", "clean")
}

func (ctx openbsd) configure(confDir, compileDir, kernelName string) error {
	conf := []byte(`
include "arch/amd64/conf/GENERIC"
pseudo-device kcov 1
`)
	if err := osutil.WriteFile(filepath.Join(confDir, kernelName), conf); err != nil {
		return err
	}

	if err := osutil.MkdirAll(compileDir); err != nil {
		return err
	}
	makefile := []byte(".include \"../Makefile.inc\"\n")
	if err := osutil.WriteFile(filepath.Join(compileDir, "Makefile"), makefile); err != nil {
		return err
	}
	if err := ctx.make(compileDir, "obj"); err != nil {
		return err
	}
	if err := ctx.make(compileDir, "config"); err != nil {
		return err
	}

	return nil
}

func (ctx openbsd) make(kernelDir string, args ...string) error {
	args = append([]string{"-j", strconv.Itoa(runtime.NumCPU())}, args...)
	_, err := osutil.RunCmd(10*time.Minute, kernelDir, "make", args...)
	return err
}
