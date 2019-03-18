// Copyright 2019 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package build

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/osutil"
)

type freebsd struct{}

func (ctx freebsd) build(targetArch, vmType, kernelDir, outputDir, compiler, userspaceDir,
	cmdlineFile, sysctlFile string, config []byte) error {
	confDir := fmt.Sprintf("%v/sys/%v/conf/", kernelDir, targetArch)
	confFile := "SYZKALLER"

	if config == nil {
		config = []byte(`
include "./GENERIC"

ident		SYZKALLER
options 	COVERAGE
options 	KCOV
`)
	}
	if err := osutil.WriteFile(filepath.Join(confDir, confFile), config); err != nil {
		return err
	}

	objPrefix := filepath.Join(kernelDir, "obj")
	if err := ctx.make(kernelDir, objPrefix, "kernel-toolchain", "-DNO_CLEAN"); err != nil {
		return err
	}
	if err := ctx.make(kernelDir, objPrefix, "buildkernel", fmt.Sprintf("KERNCONF=%v", confFile)); err != nil {
		return err
	}

	kernelObjDir := filepath.Join(objPrefix, kernelDir, fmt.Sprintf("%v.%v", targetArch, targetArch), "sys", confFile)
	for _, s := range []struct{ dir, src, dst string }{
		{userspaceDir, "image", "image"},
		{userspaceDir, "key", "key"},
		{kernelObjDir, "kernel.full", "obj/kernel.full"},
	} {
		fullSrc := filepath.Join(s.dir, s.src)
		fullDst := filepath.Join(outputDir, s.dst)
		if err := osutil.CopyFile(fullSrc, fullDst); err != nil {
			return fmt.Errorf("failed to copy %v -> %v: %v", fullSrc, fullDst, err)
		}
	}

	script := fmt.Sprintf(`
set -eux
md=$(sudo mdconfig -a -t vnode image)
partn=$(gpart show /dev/${md} | awk '/freebsd-ufs/{print $3}' | head -n 1)
tmpdir=$(mktemp -d)
sudo mount /dev/${md}p${partn} $tmpdir

sudo MAKEOBJDIRPREFIX=%s make -C %s installkernel KERNCONF=%s DESTDIR=$tmpdir

sudo umount $tmpdir
sudo mdconfig -d -u ${md#md}
`, objPrefix, kernelDir, confFile)

	if debugOut, err := osutil.RunCmd(10*time.Minute, outputDir, "/bin/sh", "-c", script); err != nil {
		return fmt.Errorf("error copying kernel: %v\n%v", err, debugOut)
	}
	return nil
}

func (ctx freebsd) clean(kernelDir, targetArch string) error {
	objPrefix := filepath.Join(kernelDir, "obj")
	return ctx.make(kernelDir, objPrefix, "cleanworld")
}

func (ctx freebsd) make(kernelDir string, objPrefix string, makeArgs ...string) error {
	args := append([]string{
		fmt.Sprintf("MAKEOBJDIRPREFIX=%v", objPrefix),
		"make",
		"-C", kernelDir,
		"-j", strconv.Itoa(runtime.NumCPU()),
	}, makeArgs...)
	_, err := osutil.RunCmd(3*time.Hour, kernelDir, "sh", "-c", strings.Join(args, " "))
	return err
}
