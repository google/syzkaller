// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"

	"github.com/google/syzkaller/pkg/compiler"
)

type windows struct{}

func (*windows) prepare(sourcedir string, build bool, arches []string) error {
	return nil
}

func (*windows) prepareArch(arch *Arch) error {
	return nil
}

func (*windows) processFile(arch *Arch, info *compiler.ConstInfo) (map[string]uint64, map[string]bool, error) {
	bin, out, err := windowsCompile(arch.sourceDir, info.Consts, info.Includes, info.Incdirs, info.Defines)
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

func windowsCompile(sourceDir string, vals, includes, incdirs []string, defines map[string]string) (bin string, out []byte, err error) {
	includeText := ""
	for _, inc := range includes {
		includeText += fmt.Sprintf("#include <%v>\n", inc)
	}
	definesText := ""
	for k, v := range defines {
		definesText += fmt.Sprintf("#ifndef %v\n#define %v %v\n#endif\n", k, k, v)
	}
	valsText := "(unsigned long long)" + strings.Join(vals, ", (unsigned long long)")
	src := windowsSrc
	src = strings.Replace(src, "[[INCLUDES]]", includeText, 1)
	src = strings.Replace(src, "[[DEFAULTS]]", definesText, 1)
	src = strings.Replace(src, "[[VALS]]", valsText, 1)
	binFile, err := ioutil.TempFile("", "")
	if err != nil {
		return "", nil, fmt.Errorf("failed to create temp file: %v", err)
	}
	binFile.Close()

	srcFile, err := ioutil.TempFile("", "")
	if err != nil {
		return "", nil, fmt.Errorf("failed to create temp file: %v", err)
	}
	srcFile.Close()
	os.Remove(srcFile.Name())
	srcName := srcFile.Name() + ".cc"
	if err := ioutil.WriteFile(srcName, []byte(src), 0600); err != nil {
		return "", nil, fmt.Errorf("failed to write source file: %v", err)
	}
	defer os.Remove(srcName)
	args := []string{"-o", binFile.Name(), srcName}
	cmd := exec.Command("cl", args...)
	out, err = cmd.CombinedOutput()
	if err != nil {
		os.Remove(binFile.Name())
		return "", out, err
	}
	return binFile.Name(), nil, nil
}

var windowsSrc = `
#include <stdio.h>
[[INCLUDES]]
[[DEFAULTS]]
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
