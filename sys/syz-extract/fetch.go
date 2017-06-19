// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// fetchValues converts literal constants (e.g. O_APPEND) or any other C expressions
// into their respective numeric values. It does so by builting and executing a C program
// that prints values of the provided expressions.
func fetchValues(arch string, vals []string, includes []string, defines map[string]string, cflags []string) (map[string]uint64, error) {
	bin, out, err := runCompiler(arch, nil, includes, nil, cflags, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to run gcc: %v\n%v", err, string(out))
	}
	os.Remove(bin)

	valMap := make(map[string]bool)
	for _, val := range vals {
		valMap[val] = true
	}

	undeclared := make(map[string]bool)
	bin, out, err = runCompiler(arch, vals, includes, defines, cflags, undeclared)
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
					logf(0, "undefined const: %v", val)
					undeclared[val] = true
				}
			}
		}
		bin, out, err = runCompiler(arch, vals, includes, defines, cflags, undeclared)
		if err != nil {
			return nil, fmt.Errorf("failed to run gcc: %v\n%v", err, string(out))
		}
	}
	defer os.Remove(bin)

	out, err = exec.Command(bin).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to run flags binary: %v\n%v", err, string(out))
	}

	flagVals := strings.Split(string(out), " ")
	if len(flagVals) != len(vals)-len(undeclared) {
		failf("fetched wrong number of values %v != %v - %v", len(flagVals), len(vals), len(undeclared))
	}
	res := make(map[string]uint64)
	j := 0
	for _, v := range flagVals {
		name := vals[j]
		j++
		for undeclared[name] {
			name = vals[j]
			j++
		}
		n, err := strconv.ParseUint(v, 10, 64)
		if err != nil {
			failf("failed to parse value: %v (%v)", err, v)
		}
		res[name] = n
	}
	return res, nil
}

func runCompiler(arch string, vals []string, includes []string, defines map[string]string, cflags []string, undeclared map[string]bool) (bin string, out []byte, err error) {
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
	src := strings.Replace(fetchSrc, "[[INCLUDES]]", includeText, 1)
	src = strings.Replace(src, "[[DEFAULTS]]", definesText, 1)
	src = strings.Replace(src, "[[VALS]]", valsText, 1)
	binFile, err := ioutil.TempFile("", "")
	if err != nil {
		return "", nil, fmt.Errorf("failed to create temp file: %v", err)
	}
	binFile.Close()

	args := []string{"-x", "c", "-", "-o", binFile.Name(), "-fmessage-length=0"}
	args = append(args, cflags...)
	args = append(args, []string{
		// This would be useful to ensure that we don't include any host headers,
		// but kernel includes at least <stdarg.h>
		// "-nostdinc",
		"-w",
		"-O3", // required to get expected values for some __builtin_constant_p
		"-I.",
		"-D__KERNEL__",
		"-DKBUILD_MODNAME=\"-\"",
		"-I" + *flagLinux + "/arch/" + arch + "/include",
		"-I" + *flagLinuxBld + "/arch/" + arch + "/include/generated/uapi",
		"-I" + *flagLinuxBld + "/arch/" + arch + "/include/generated",
		"-I" + *flagLinuxBld + "/include",
		"-I" + *flagLinux + "/include",
		"-I" + *flagLinux + "/arch/" + arch + "/include/uapi",
		"-I" + *flagLinuxBld + "/arch/" + arch + "/include/generated/uapi",
		"-I" + *flagLinux + "/include/uapi",
		"-I" + *flagLinuxBld + "/include/generated/uapi",
		"-I" + *flagLinux,
		"-include", *flagLinux + "/include/linux/kconfig.h",
	}...)

	cmd := exec.Command("gcc", args...)
	cmd.Stdin = strings.NewReader(src)
	out, err = cmd.CombinedOutput()
	if err != nil {
		os.Remove(binFile.Name())
		return "", out, err
	}
	return binFile.Name(), nil, nil
}

var fetchSrc = `
[[INCLUDES]]
[[DEFAULTS]]
int printf(const char *format, ...);
unsigned long phys_base;
#ifndef __phys_addr
unsigned long __phys_addr(unsigned long addr) { return 0; }
#endif
int main() {
	int i;
	unsigned long vals[] = {[[VALS]]};
	for (i = 0; i < sizeof(vals)/sizeof(vals[0]); i++) {
		if (i != 0)
			printf(" ");
		printf("%lu", vals[i]);
	}
	return 0;
}
`
