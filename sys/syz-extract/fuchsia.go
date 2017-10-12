// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/google/syzkaller/pkg/compiler"
)

type fuchsia struct{}

func (*fuchsia) prepare(sourcedir string, build bool, arches []string) error {
	if sourcedir == "" {
		return fmt.Errorf("provide path to kernel checkout via -sourcedir flag (or make extract SOURCEDIR)")
	}
	return nil
}

func (*fuchsia) prepareArch(arch *Arch) error {
	return nil
}

func (*fuchsia) processFile(arch *Arch, info *compiler.ConstInfo) (map[string]uint64, map[string]bool, error) {
	bin, out, err := fuchsiaCompile(arch.sourceDir, info.Consts, info.Includes, info.Incdirs, info.Defines)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to run compiler: %v\n%v", err, string(out))
	}
	defer os.Remove(bin)
	res, err := runBinaryAndParse(bin, info.Consts, nil)
	if err != nil {
		return nil, nil, err
	}
	return res, nil, nil
}

func fuchsiaCompile(sourceDir string, vals, includes, incdirs []string, defines map[string]string) (bin string, out []byte, err error) {
	includeText := ""
	for _, inc := range includes {
		includeText += fmt.Sprintf("#include <%v>\n", inc)
	}
	definesText := ""
	for k, v := range defines {
		definesText += fmt.Sprintf("#ifndef %v\n#define %v %v\n#endif\n", k, k, v)
	}
	valsText := strings.Join(vals, ",")
	src := fuchsiaSrc
	src = strings.Replace(src, "[[INCLUDES]]", includeText, 1)
	src = strings.Replace(src, "[[DEFAULTS]]", definesText, 1)
	src = strings.Replace(src, "[[VALS]]", valsText, 1)
	binFile, err := ioutil.TempFile("", "")
	if err != nil {
		return "", nil, fmt.Errorf("failed to create temp file: %v", err)
	}
	binFile.Close()
	compiler := filepath.Join(sourceDir, "buildtools", "linux-x64", "clang", "bin", "clang")
	includeDir := filepath.Join(sourceDir, "out", "build-zircon", "build-zircon-pc-x86-64", "sysroot", "include")
	args := []string{"-x", "c", "-", "-o", binFile.Name(), "-fmessage-length=0", "-w", "-I", includeDir}
	for _, incdir := range incdirs {
		args = append(args, "-I"+sourceDir+"/"+incdir)
	}
	cmd := exec.Command(compiler, args...)
	cmd.Stdin = strings.NewReader(src)
	out, err = cmd.CombinedOutput()
	if err != nil {
		os.Remove(binFile.Name())
		return "", out, err
	}
	return binFile.Name(), nil, nil
}

var fuchsiaSrc = `
[[INCLUDES]]
[[DEFAULTS]]
int printf(const char *format, ...);
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
