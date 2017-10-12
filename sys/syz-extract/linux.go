// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/compiler"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/sys/targets"
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
	vals := info.Consts
	includes := append(info.Includes, "asm/unistd.h")
	bin, out, err := linuxCompile(arch.target, arch.sourceDir, arch.buildDir, nil,
		includes, info.Incdirs, nil, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to run gcc: %v\n%v", err, string(out))
	}
	os.Remove(bin)

	valMap := make(map[string]bool)
	for _, val := range vals {
		valMap[val] = true
	}

	undeclared := make(map[string]bool)
	bin, out, err = linuxCompile(arch.target, arch.sourceDir, arch.buildDir, vals,
		includes, info.Incdirs, info.Defines, undeclared)
	if err != nil {
		for _, errMsg := range []string{
			"error: ‘([a-zA-Z0-9_]+)’ undeclared",
			"note: in expansion of macro ‘([a-zA-Z0-9_]+)’",
		} {
			re := regexp.MustCompile(errMsg)
			matches := re.FindAllSubmatch(out, -1)
			for _, match := range matches {
				val := string(match[1])
				if !undeclared[val] && valMap[val] {
					undeclared[val] = true
				}
			}
		}
		bin, out, err = linuxCompile(arch.target, arch.sourceDir, arch.buildDir, vals,
			includes, info.Incdirs, info.Defines, undeclared)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to run gcc: %v\n%v", err, string(out))
		}
	}
	defer os.Remove(bin)

	res, err := runBinaryAndParse(bin, vals, undeclared)
	if err != nil {
		return nil, nil, err
	}
	return res, undeclared, nil
}

func linuxCompile(target *targets.Target, kernelDir, buildDir string, vals, includes, incdirs []string, defines map[string]string, undeclared map[string]bool) (bin string, out []byte, err error) {
	includeText := ""
	for _, inc := range includes {
		includeText += fmt.Sprintf("#include <%v>\n", inc)
	}
	definesText := ""
	for k, v := range defines {
		definesText += fmt.Sprintf("#ifndef %v\n#define %v %v\n#endif\n", k, k, v)
	}
	valsText := ""
	for _, v := range vals {
		if undeclared[v] {
			continue
		}
		if valsText != "" {
			valsText += ","
		}
		valsText += v
	}
	src := strings.Replace(linuxSrc, "[[INCLUDES]]", includeText, 1)
	src = strings.Replace(src, "[[DEFAULTS]]", definesText, 1)
	src = strings.Replace(src, "[[VALS]]", valsText, 1)
	binFile, err := ioutil.TempFile("", "")
	if err != nil {
		return "", nil, fmt.Errorf("failed to create temp file: %v", err)
	}
	binFile.Close()

	arch := target.KernelHeaderArch
	args := []string{"-x", "c", "-", "-o", binFile.Name(), "-fmessage-length=0"}
	args = append(args, target.CFlags...)
	args = append(args, []string{
		// This would be useful to ensure that we don't include any host headers,
		// but kernel includes at least <stdarg.h>
		// "-nostdinc",
		"-w",
		"-O3", // required to get expected values for some __builtin_constant_p
		"-I.",
		"-D__KERNEL__",
		"-DKBUILD_MODNAME=\"-\"",
		"-I" + kernelDir + "/arch/" + arch + "/include",
		"-I" + buildDir + "/arch/" + arch + "/include/generated/uapi",
		"-I" + buildDir + "/arch/" + arch + "/include/generated",
		"-I" + buildDir + "/include",
		"-I" + kernelDir + "/include",
		"-I" + kernelDir + "/arch/" + arch + "/include/uapi",
		"-I" + buildDir + "/arch/" + arch + "/include/generated/uapi",
		"-I" + kernelDir + "/include/uapi",
		"-I" + buildDir + "/include/generated/uapi",
		"-I" + kernelDir,
		"-include", kernelDir + "/include/linux/kconfig.h",
	}...)
	for _, incdir := range incdirs {
		args = append(args, "-I"+kernelDir+"/"+incdir)
	}
	cmd := exec.Command("gcc", args...)
	cmd.Stdin = strings.NewReader(src)
	out, err = cmd.CombinedOutput()
	if err != nil {
		os.Remove(binFile.Name())
		return "", out, err
	}
	return binFile.Name(), nil, nil
}

var linuxSrc = `
[[INCLUDES]]
[[DEFAULTS]]
int printf(const char *format, ...);
unsigned long phys_base;
#ifndef __phys_addr
unsigned long __phys_addr(unsigned long addr) { return 0; }
#endif
int main() {
	int i;
	unsigned long long vals[] = {[[VALS]]};
	for (i = 0; i < sizeof(vals)/sizeof(vals[0]); i++) {
		if (i != 0)
			printf(" ");
		printf("%llu", vals[i]);
	}
	return 0;
}
`
