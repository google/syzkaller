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

func (*linux) prepare(sourcedir string, build bool, arches []string) error {
	if sourcedir == "" {
		return fmt.Errorf("provide path to kernel checkout via -sourcedir flag (or make extract SOURCEDIR)")
	}
	if build {
		// Run 'make mrproper', otherwise out-of-tree build fails.
		// However, it takes unreasonable amount of time,
		// so first check few files and if they are missing hope for best.
		if osutil.IsExist(filepath.Join(sourcedir, ".config")) ||
			osutil.IsExist(filepath.Join(sourcedir, "init/main.o")) ||
			osutil.IsExist(filepath.Join(sourcedir, "include/generated/compile.h")) {
			fmt.Printf("make mrproper\n")
			out, err := osutil.RunCmd(time.Hour, sourcedir, "make", "mrproper",
				"-j", fmt.Sprint(runtime.NumCPU()))
			if err != nil {
				return fmt.Errorf("make mrproper failed: %v\n%s", err, out)
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
	// Kernel misses these headers on all arches.
	// So we create empty stubs in buildDir/syzkaller and add -IbuildDir/syzkaller
	// as the last flag so it won't override real kernel headers.
	for _, hdr := range []string{
		"asm/a.out.h",
		"asm/prctl.h",
		"asm/mce.h",
	} {
		fullPath := filepath.Join(arch.buildDir, "syzkaller", hdr)
		if err := osutil.MkdirAll(filepath.Dir(fullPath)); err != nil {
			return err
		}
		if err := osutil.WriteFile(fullPath, nil); err != nil {
			return nil
		}
	}
	if !arch.build {
		return nil
	}
	target := arch.target
	var cflags []string
	for _, flag := range target.CrossCFlags {
		if !strings.HasPrefix(flag, "-W") {
			cflags = append(cflags, flag)
		}
	}
	kernelDir := arch.sourceDir
	buildDir := arch.buildDir
	makeArgs := []string{
		"ARCH=" + target.KernelArch,
		"CROSS_COMPILE=" + target.CCompilerPrefix,
		"CFLAGS=" + strings.Join(cflags, " "),
		"O=" + buildDir,
		"-j", fmt.Sprint(runtime.NumCPU()),
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
		"-I" + buildDir + "/syzkaller",
		"-I" + sourceDir + "/arch/" + headerArch + "/include/asm/mach-malta",
		"-I" + sourceDir + "/arch/" + headerArch + "/include/asm/mach-generic",
		"-include", sourceDir + "/include/linux/kconfig.h",
	}
	args = append(args, arch.target.CrossCFlags...)
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
	}
	cc := arch.target.CCompilerPrefix + "gcc"
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
