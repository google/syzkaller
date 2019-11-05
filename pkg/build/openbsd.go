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

func (ctx openbsd) build(params *Params) error {
	const kernelName = "SYZKALLER"
	confDir := fmt.Sprintf("%v/sys/arch/%v/conf", params.KernelDir, params.TargetArch)
	compileDir := fmt.Sprintf("%v/sys/arch/%v/compile/%v", params.KernelDir, params.TargetArch, kernelName)

	if err := osutil.WriteFile(filepath.Join(confDir, kernelName), params.Config); err != nil {
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
			return err
		}
	}
	for _, s := range []struct{ dir, src, dst string }{
		{compileDir, "obj/bsd", "kernel"},
		{compileDir, "obj/bsd.gdb", "obj/bsd.gdb"},
		{params.UserspaceDir, "image", "image"},
		{params.UserspaceDir, "key", "key"},
	} {
		fullSrc := filepath.Join(s.dir, s.src)
		fullDst := filepath.Join(params.OutputDir, s.dst)
		if err := osutil.CopyFile(fullSrc, fullDst); err != nil {
			return fmt.Errorf("failed to copy %v -> %v: %v", fullSrc, fullDst, err)
		}
	}
	if params.VMType == "gce" {
		return ctx.copyFilesToImage(
			filepath.Join(params.UserspaceDir, "overlay"), params.OutputDir)
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

// copyFilesToImage populates the filesystem image in outputDir with
// run-specific files. The kernel is copied as /bsd and if overlayDir
// exists, its contents are copied into corresponding files in the
// image.
//
// Ideally a user space tool capable of understanding FFS should
// interpret FFS inside the image file, but vnd(4) device would do in
// a pinch.
func (ctx openbsd) copyFilesToImage(overlayDir, outputDir string) error {
	script := fmt.Sprintf(`set -eux
OVERLAY="%s"
# Cleanup in case something failed before.
doas umount /altroot || true
doas vnconfig -u vnd0 || true

doas /sbin/vnconfig vnd0 image
doas mount /dev/vnd0a /altroot
doas cp kernel /altroot/bsd
test -d "$OVERLAY" && doas cp -Rf "$OVERLAY"/. /altroot
doas umount /altroot
doas vnconfig -u vnd0
`, overlayDir)
	debugOut, err := osutil.RunCmd(10*time.Minute, outputDir, "/bin/sh", "-c", script)
	if err != nil {
		log.Logf(0, "Error copying kernel into image %v\n%v\n", outputDir, debugOut)
	}
	return err
}
