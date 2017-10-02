// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"text/template"

	"github.com/google/syzkaller/pkg/compiler"
)

func extract(info *compiler.ConstInfo, cc string, args []string, addSource string) (map[string]uint64, map[string]bool, error) {
	data := &CompileData{
		AddSource: addSource,
		Defines:   info.Defines,
		Includes:  info.Includes,
		Values:    info.Consts,
	}
	undeclared := make(map[string]bool)
	bin, out, err := compile(cc, args, data)
	if err != nil {
		// Some consts and syscall numbers are not defined on some archs.
		// Figure out from compiler output undefined consts,
		// and try to compile again without them.
		valMap := make(map[string]bool)
		for _, val := range info.Consts {
			valMap[val] = true
		}
		for _, errMsg := range []string{
			"error: ‘([a-zA-Z0-9_]+)’ undeclared",
			"note: in expansion of macro ‘([a-zA-Z0-9_]+)’",
		} {
			re := regexp.MustCompile(errMsg)
			matches := re.FindAllSubmatch(out, -1)
			for _, match := range matches {
				val := string(match[1])
				if valMap[val] {
					undeclared[val] = true
				}
			}
		}
		data.Values = nil
		for _, v := range info.Consts {
			if undeclared[v] {
				continue
			}
			data.Values = append(data.Values, v)
		}
		bin, out, err = compile(cc, args, data)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to run compiler: %v\n%v", err, string(out))
		}
	}
	defer os.Remove(bin)

	out, err = exec.Command(bin).CombinedOutput()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to run flags binary: %v\n%v", err, string(out))
	}
	flagVals := strings.Split(string(out), " ")
	if len(out) == 0 {
		flagVals = nil
	}
	if len(flagVals) != len(data.Values) {
		return nil, nil, fmt.Errorf("fetched wrong number of values %v, want != %v",
			len(flagVals), len(data.Values))
	}
	res := make(map[string]uint64)
	for i, name := range data.Values {
		val := flagVals[i]
		n, err := strconv.ParseUint(val, 10, 64)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to parse value: %v (%v)", err, val)
		}
		res[name] = n
	}
	return res, undeclared, nil
}

type CompileData struct {
	AddSource string
	Defines   map[string]string
	Includes  []string
	Values    []string
}

func compile(cc string, args []string, data *CompileData) (bin string, out []byte, err error) {
	srcFile, err := ioutil.TempFile("", "")
	if err != nil {
		return "", nil, fmt.Errorf("failed to create temp file: %v", err)
	}
	srcFile.Close()
	os.Remove(srcFile.Name())
	srcName := srcFile.Name() + ".c"
	defer os.Remove(srcName)
	src := new(bytes.Buffer)
	if err := srcTemplate.Execute(src, data); err != nil {
		return "", nil, fmt.Errorf("failed to generate source: %v", err)
	}
	if err := ioutil.WriteFile(srcName, src.Bytes(), 0600); err != nil {
		return "", nil, fmt.Errorf("failed to write source file: %v", err)
	}

	binFile, err := ioutil.TempFile("", "")
	if err != nil {
		return "", nil, fmt.Errorf("failed to create temp file: %v", err)
	}
	binFile.Close()

	args = append(args, []string{
		srcName,
		"-o", binFile.Name(),
		"-w",
	}...)
	cmd := exec.Command(cc, args...)
	out, err = cmd.CombinedOutput()
	if err != nil {
		os.Remove(binFile.Name())
		return "", out, err
	}
	return binFile.Name(), nil, nil
}

var srcTemplate = template.Must(template.New("").Parse(`
{{range $incl := $.Includes}}
#include <{{$incl}}>
{{end}}

{{range $name, $val := $.Defines}}
#ifndef {{$name}}
#	define {{$name}} {{$val}}
#endif
{{end}}

{{.AddSource}}

int printf(const char *format, ...);

int main() {
	int i;
	unsigned long long vals[] = {
		{{range $val := $.Values}}(unsigned long long){{$val}},{{end}}
	};
	for (i = 0; i < sizeof(vals)/sizeof(vals[0]); i++) {
		if (i != 0)
			printf(" ");
		printf("%llu", vals[i]);
	}
	return 0;
}
`))
