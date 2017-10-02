// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/compiler"
	"github.com/google/syzkaller/pkg/osutil"
)

type linux struct{}

func (*linux) prepare(sourcedir string, build bool, arches []string) error {
	if sourcedir == "" {
		return fmt.Errorf("provide path to kernel checkout via -sourcedir flag (or make extract SOURCEDIR)")
	}
	if build {
		// Otherwise out-of-tree build fails.
		fmt.Printf("make mrproper\n")
		out, err := osutil.RunCmd(time.Hour, sourcedir, "make", "mrproper")
		if err != nil {
			return fmt.Errorf("make mrproper failed: %v\n%s\n", err, out)
		}
	} else {
		if len(arches) > 1 {
			return fmt.Errorf("more than 1 arch is invalid without -build")
		}
	}
	return nil
}

func (*linux) prepareArch(arch *Arch) error {
	if !arch.build {
		return nil
	}
	target := arch.target
	kernelDir := arch.sourceDir
	buildDir := arch.buildDir
	makeArgs := []string{
		"ARCH=" + target.KernelArch,
		"CROSS_COMPILE=" + target.CCompilerPrefix,
		"CFLAGS=" + strings.Join(target.CrossCFlags, " "),
		"O=" + buildDir,
	}
	out, err := osutil.RunCmd(time.Hour, kernelDir, "make", append(makeArgs, "defconfig")...)
	if err != nil {
		return fmt.Errorf("make defconfig failed: %v\n%s\n", err, out)
	}
	// Without CONFIG_NETFILTER kernel does not build.
	out, err = osutil.RunCmd(time.Minute, buildDir, "sed", "-i",
		"s@# CONFIG_NETFILTER is not set@CONFIG_NETFILTER=y@g", ".config")
	if err != nil {
		return fmt.Errorf("sed .config failed: %v\n%s\n", err, out)
	}
	out, err = osutil.RunCmd(time.Hour, kernelDir, "make", append(makeArgs, "olddefconfig")...)
	if err != nil {
		return fmt.Errorf("make olddefconfig failed: %v\n%s\n", err, out)
	}
	out, err = osutil.RunCmd(time.Hour, kernelDir, "make", append(makeArgs, "init/main.o")...)
	if err != nil {
		return fmt.Errorf("make failed: %v\n%s\n", err, out)
	}
	return nil
}

func (*linux) processFile(arch *Arch, info *compiler.ConstInfo) (map[string]uint64, map[string]bool, error) {
	headerArch := arch.target.KernelHeaderArch
	sourceDir := arch.sourceDir
	buildDir := arch.buildDir
	args := []string{
		// This would be useful to ensure that we don't include any host headers,
		// but kernel includes at least <stdarg.h>
		// "-nostdinc",
		"-w", "-fmessage-length=0",
		"-O3", // required to get expected values for some __builtin_constant_p
		"-I.",
		"-D__KERNEL__",
		"-DKBUILD_MODNAME=\"-\"",
		"-I" + sourceDir + "/arch/" + headerArch + "/include",
		"-I" + buildDir + "/arch/" + headerArch + "/include/generated/uapi",
		"-I" + buildDir + "/arch/" + headerArch + "/include/generated",
		"-I" + buildDir + "/include",
		"-I" + sourceDir + "/include",
		"-I" + sourceDir + "/arch/" + headerArch + "/include/uapi",
		"-I" + buildDir + "/arch/" + headerArch + "/include/generated/uapi",
		"-I" + sourceDir + "/include/uapi",
		"-I" + buildDir + "/include/generated/uapi",
		"-I" + sourceDir,
		"-include", sourceDir + "/include/linux/kconfig.h",
	}
	args = append(args, arch.target.CFlags...)
	for _, incdir := range info.Incdirs {
		args = append(args, "-I"+sourceDir+"/"+incdir)
	}
	const addSource = `
#include <asm/unistd.h>
unsigned long phys_base;
#ifndef __phys_addr
unsigned long __phys_addr(unsigned long addr) { return 0; }
#endif
`
	return extract(info, "gcc", args, addSource)
}
