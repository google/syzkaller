// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package build

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strconv"
	"time"

	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
)

type openbsd struct{}

func (ctx openbsd) build(targetArch, vmType, kernelDir, outputDir, compiler, userspaceDir,
	cmdlineFile, sysctlFile string, config []byte) error {
	const kernelName = "SYZKALLER"
	confDir := fmt.Sprintf("%v/sys/arch/%v/conf", kernelDir, targetArch)
	compileDir := fmt.Sprintf("%v/sys/arch/%v/compile/%v", kernelDir, targetArch, kernelName)

	if err := osutil.WriteFile(filepath.Join(confDir, kernelName), config); err != nil {
		return err
	}

	if err := osutil.MkdirAll(compileDir); err != nil {
		return err
	}
	makefile := []byte(".include \"../Makefile.inc\"\n")
	if err := osutil.WriteFile(filepath.Join(compileDir, "Makefile"), makefile); err != nil {
		return err
	}
	for _, tgt := range []string{"clean", "obj", "config", "all"} {
		if err := ctx.make(compileDir, tgt); err != nil {
			return extractRootCause(err)
		}
	}
	for _, s := range []struct{ dir, src, dst string }{
		{compileDir, "obj/bsd", "kernel"},
		{compileDir, "obj/bsd.gdb", "obj/bsd.gdb"},
		{userspaceDir, "image", "image"},
		{userspaceDir, "key", "key"},
	} {
		fullSrc := filepath.Join(s.dir, s.src)
		fullDst := filepath.Join(outputDir, s.dst)
		if err := osutil.CopyFile(fullSrc, fullDst); err != nil {
			return fmt.Errorf("failed to copy %v -> %v: %v", fullSrc, fullDst, err)
		}
	}
	if vmType == "gce" {
		return CopyKernelToImage(outputDir)
	}
	return nil
}

func (ctx openbsd) clean(kernelDir, targetArch string) error {
	// Building clean is fast enough and incremental builds in face of
	// changing config files don't work. Instead of optimizing for the
	// case where humans have to think, let's bludgeon it with a
	// machine.
	return nil
}

func (ctx openbsd) make(kernelDir string, args ...string) error {
	args = append([]string{"-j", strconv.Itoa(runtime.NumCPU())}, args...)
	_, err := osutil.RunCmd(10*time.Minute, kernelDir, "make", args...)
	return err
}

// The easiest way to make an openbsd image that boots the given
// kernel on GCE is to simply overwrite it inside the disk image.
// Ideally a user space tool capable of understanding FFS should
// implement this directly, but vnd(4) device would do in a pinch.
// Assumes that the outputDir contains the appropriately named files.
func CopyKernelToImage(outputDir string) error {
	script := `set -eux
# Cleanup in case something failed before.
doas umount /altroot || true
doas vnconfig -u vnd0 || true

doas /sbin/vnconfig vnd0 image
doas mount /dev/vnd0a /altroot
doas cp kernel /altroot/bsd
doas umount /altroot
doas vnconfig -u vnd0
`
	debugOut, err := osutil.RunCmd(10*time.Minute, outputDir, "/bin/sh", "-c", script)
	if err != nil {
		log.Logf(0, "Error copying kernel into image %v\n%v\n", outputDir, debugOut)
	}
	return err
}
