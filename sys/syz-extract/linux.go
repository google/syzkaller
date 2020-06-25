// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/compiler"
	"github.com/google/syzkaller/pkg/osutil"
)

type linux struct{}

func (*linux) prepare(sourcedir string, build bool, arches []*Arch) error {
	if sourcedir == "" {
		return fmt.Errorf("provide path to kernel checkout via -sourcedir flag (or make extract SOURCEDIR)")
	}
	if build {
		// Run 'make mrproper', otherwise out-of-tree build fails.
		// However, it takes unreasonable amount of time,
		// so first check few files and if they are missing hope for best.
		for _, a := range arches {
			arch := a.target.KernelArch
			if osutil.IsExist(filepath.Join(sourcedir, ".config")) ||
				osutil.IsExist(filepath.Join(sourcedir, "init/main.o")) ||
				osutil.IsExist(filepath.Join(sourcedir, "include/config")) ||
				osutil.IsExist(filepath.Join(sourcedir, "include/generated/compile.h")) ||
				osutil.IsExist(filepath.Join(sourcedir, "arch", arch, "include", "generated")) {
				fmt.Printf("make mrproper ARCH=%v\n", arch)
				out, err := osutil.RunCmd(time.Hour, sourcedir, "make", "mrproper", "ARCH="+arch,
					"-j", fmt.Sprint(runtime.NumCPU()))
				if err != nil {
					return fmt.Errorf("make mrproper failed: %v\n%s", err, out)
				}
			}
		}
	} else {
		if len(arches) > 1 {
			return fmt.Errorf("more than 1 arch is invalid without -build")
		}
	}
	return nil
}

func (*linux) prepareArch(arch *Arch) error {
	// Kernel misses these headers on some arches.
	// So we create empty stubs in buildDir/syzkaller and add -IbuildDir/syzkaller
	// as the last flag so it won't override real kernel headers.
	for hdr, data := range map[string]string{
		// This is the only compiler header kernel uses,
		// need to provide it since we use -nostdinc below.
		"stdarg.h": `
#pragma once
#define va_list __builtin_va_list
#define va_start __builtin_va_start
#define va_end __builtin_va_end
#define va_arg __builtin_va_arg
#define va_copy __builtin_va_copy
#define __va_copy __builtin_va_copy
`,
		"asm/a.out.h": "",
		"asm/prctl.h": "",
		"asm/mce.h":   "",
	} {
		fullPath := filepath.Join(arch.buildDir, "syzkaller", hdr)
		if err := osutil.MkdirAll(filepath.Dir(fullPath)); err != nil {
			return err
		}
		if err := osutil.WriteFile(fullPath, []byte(data)); err != nil {
			return nil
		}
	}
	if !arch.build {
		return nil
	}
	target := arch.target
	var cflags []string
	for _, flag := range target.CFlags {
		if !strings.HasPrefix(flag, "-W") {
			cflags = append(cflags, flag)
		}
	}
	kernelDir := arch.sourceDir
	buildDir := arch.buildDir
	makeArgs := []string{
		"ARCH=" + target.KernelArch,
		"CFLAGS=" + strings.Join(cflags, " "),
		"O=" + buildDir,
		"-j", fmt.Sprint(runtime.NumCPU()),
	}
	if target.Triple != "" {
		makeArgs = append(makeArgs, "CROSS_COMPILE="+target.Triple+"-")
	}
	if target.KernelCompiler != "" {
		makeArgs = append(makeArgs, "CC="+target.KernelCompiler)
	}
	if target.KernelLinker != "" {
		makeArgs = append(makeArgs, "LD="+target.KernelLinker)
	}
	out, err := osutil.RunCmd(time.Hour, kernelDir, "make", append(makeArgs, "defconfig")...)
	if err != nil {
		return fmt.Errorf("make defconfig failed: %v\n%s", err, out)
	}
	_, err = osutil.RunCmd(time.Minute, buildDir, filepath.Join(kernelDir, "scripts", "config"),
		// powerpc arch is configured to be big-endian by default, but we want little-endian powerpc.
		// Since all of our archs are little-endian for now, we just blindly switch it.
		"-d", "CPU_BIG_ENDIAN", "-e", "CPU_LITTLE_ENDIAN",
		// Without CONFIG_NETFILTER kernel does not build.
		"-e", "NETFILTER",
		// include/net/mptcp.h is the only header in kernel that guards some
		// of the consts with own config, so we need to enable CONFIG_MPTCP.
		"-e", "MPTCP",
		// security/smack/smack.h requires this to build.
		"-e", "SECURITY",
		"-e", "SECURITY_SMACK",
	)
	if err != nil {
		return err
	}
	out, err = osutil.RunCmd(time.Hour, kernelDir, "make", append(makeArgs, "olddefconfig")...)
	if err != nil {
		return fmt.Errorf("make olddefconfig failed: %v\n%s", err, out)
	}
	out, err = osutil.RunCmd(time.Hour, kernelDir, "make", append(makeArgs, "init/main.o")...)
	if err != nil {
		return fmt.Errorf("make failed: %v\n%s", err, out)
	}
	return nil
}

func (*linux) processFile(arch *Arch, info *compiler.ConstInfo) (map[string]uint64, map[string]bool, error) {
	if strings.HasSuffix(info.File, "_kvm.txt") && (arch.target.Arch == "arm" || arch.target.Arch == "riscv64") {
		// Hack: KVM is not supported on ARM anymore. We may want some more official support
		// for marking descriptions arch-specific, but so far this combination is the only
		// one. For riscv64, KVM is not supported yet but might be in the future.
		// Note: syz-sysgen also ignores this file for arm and riscv64.
		return nil, nil, nil
	}
	headerArch := arch.target.KernelHeaderArch
	sourceDir := arch.sourceDir
	buildDir := arch.buildDir
	args := []string{
		// This makes the build completely hermetic, only kernel headers are used.
		"-nostdinc",
		"-w", "-fmessage-length=0",
		"-O3", // required to get expected values for some __builtin_constant_p
		"-I.",
		"-D__KERNEL__",
		"-DKBUILD_MODNAME=\"-\"",
		"-I" + sourceDir + "/arch/" + headerArch + "/include",
		"-I" + buildDir + "/arch/" + headerArch + "/include/generated/uapi",
		"-I" + buildDir + "/arch/" + headerArch + "/include/generated",
		"-I" + sourceDir + "/arch/" + headerArch + "/include/asm/mach-malta",
		"-I" + sourceDir + "/arch/" + headerArch + "/include/asm/mach-generic",
		"-I" + buildDir + "/include",
		"-I" + sourceDir + "/include",
		"-I" + sourceDir + "/arch/" + headerArch + "/include/uapi",
		"-I" + buildDir + "/arch/" + headerArch + "/include/generated/uapi",
		"-I" + sourceDir + "/include/uapi",
		"-I" + buildDir + "/include/generated/uapi",
		"-I" + sourceDir,
		"-I" + sourceDir + "/include/linux",
		"-I" + buildDir + "/syzkaller",
		"-include", sourceDir + "/include/linux/kconfig.h",
	}
	args = append(args, arch.target.CFlags...)
	for _, incdir := range info.Incdirs {
		args = append(args, "-I"+sourceDir+"/"+incdir)
	}
	if arch.includeDirs != "" {
		for _, dir := range strings.Split(arch.includeDirs, ",") {
			args = append(args, "-I"+dir)
		}
	}
	params := &extractParams{
		AddSource:      "#include <asm/unistd.h>",
		ExtractFromELF: true,
		TargetEndian:   arch.target.HostEndian,
	}
	cc := arch.target.CCompiler
	res, undeclared, err := extract(info, cc, args, params)
	if err != nil {
		return nil, nil, err
	}
	if arch.target.PtrSize == 4 {
		// mmap syscall on i386/arm is translated to old_mmap and has different signature.
		// As a workaround fix it up to mmap2, which has signature that we expect.
		// pkg/csource has the same hack.
		const mmap = "__NR_mmap"
		const mmap2 = "__NR_mmap2"
		if res[mmap] != 0 || undeclared[mmap] {
			if res[mmap2] == 0 {
				return nil, nil, fmt.Errorf("%v is missing", mmap2)
			}
			res[mmap] = res[mmap2]
			delete(undeclared, mmap)
		}
	}
	return res, undeclared, nil
}
