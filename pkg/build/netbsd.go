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

type netbsd struct{}

func (ctx netbsd) build(targetArch, vmType, kernelDir, outputDir, compiler, userspaceDir,
	cmdlineFile, sysctlFile string, config []byte) error {
	const kernelName = "GENERIC_SYZKALLER"
	confDir := fmt.Sprintf("%v/sys/arch/%v/conf", kernelDir, targetArch)
	compileDir := fmt.Sprintf("%v/sys/arch/%v/compile/obj/%v", kernelDir, targetArch, kernelName)

	// Compile the kernel with KASAN
	conf := []byte(`
include "arch/amd64/conf/GENERIC"

makeoptions    KASAN=1
options    KASAN
no options SVS
`)

	if err := osutil.WriteFile(filepath.Join(confDir, kernelName), conf); err != nil {
		return err
	}

	// Build tools before building kernel
	if _, err := osutil.RunCmd(10*time.Minute, kernelDir, "./build.sh", "-m", targetArch,
		"-U", "-j"+strconv.Itoa(runtime.NumCPU()), "tools"); err != nil {
		return extractRootCause(err)
	}

	// Build kernel
	if _, err := osutil.RunCmd(10*time.Minute, kernelDir, "./build.sh", "-m", targetArch,
		"-U", "-j"+strconv.Itoa(runtime.NumCPU()), "kernel="+kernelName); err != nil {
		return extractRootCause(err)
	}

	for _, s := range []struct{ dir, src, dst string }{
		{compileDir, "netbsd", "kernel"},
		{compileDir, "netbsd.gdb", "netbsd.gdb"},
	} {
		fullSrc := filepath.Join(s.dir, s.src)
		fullDst := filepath.Join(outputDir, s.dst)
		if err := osutil.CopyFile(fullSrc, fullDst); err != nil {
			return fmt.Errorf("failed to copy %v -> %v: %v", fullSrc, fullDst, err)
		}
	}
	return nil
}

func (ctx netbsd) clean(kernelDir string) error {
	// Building clean is fast enough and incremental builds in face of
	// changing config files don't work. Instead of optimizing for the
	// case where humans have to think, let's bludgeon it with a
	// machine.
	return nil
}
