// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"io/ioutil"
	"os"
	"regexp"
	"strconv"
	"strings"
	"text/template"

	"github.com/google/syzkaller/pkg/compiler"
	"github.com/google/syzkaller/pkg/osutil"
)

type extractParams struct {
	AddSource      string
	DeclarePrintf  bool
	DefineGlibcUse bool // workaround for incorrect flags to clang for fuchsia.
	ExtractFromELF bool
	TargetEndian   binary.ByteOrder
}

func extract(info *compiler.ConstInfo, cc string, args []string, params *extractParams) (
	map[string]uint64, map[string]bool, error) {
	data := &CompileData{
		extractParams: params,
		Defines:       info.Defines,
		Includes:      info.Includes,
		Values:        info.Consts,
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
			`error: [‘']([a-zA-Z0-9_]+)[’'] undeclared`,
			`note: in expansion of macro [‘']([a-zA-Z0-9_]+)[’']`,
			`note: expanded from macro [‘']([a-zA-Z0-9_]+)[’']`,
			`error: use of undeclared identifier [‘']([a-zA-Z0-9_]+)[’']`,
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
			return nil, nil, fmt.Errorf("failed to run compiler: %v %v\n%v\n%s",
				cc, args, err, out)
		}
	}
	defer os.Remove(bin)

	var flagVals []uint64
	if data.ExtractFromELF {
		flagVals, err = extractFromELF(bin, params.TargetEndian)
	} else {
		flagVals, err = extractFromExecutable(bin)
	}
	if err != nil {
		return nil, nil, err
	}
	if len(flagVals) != len(data.Values) {
		return nil, nil, fmt.Errorf("fetched wrong number of values %v, want != %v",
			len(flagVals), len(data.Values))
	}
	res := make(map[string]uint64)
	for i, name := range data.Values {
		res[name] = flagVals[i]
	}
	return res, undeclared, nil
}

type CompileData struct {
	*extractParams
	Defines  map[string]string
	Includes []string
	Values   []string
}

func compile(cc string, args []string, data *CompileData) (string, []byte, error) {
	src := new(bytes.Buffer)
	if err := srcTemplate.Execute(src, data); err != nil {
		return "", nil, fmt.Errorf("failed to generate source: %v", err)
	}
	binFile, err := osutil.TempFile("syz-extract-bin")
	if err != nil {
		return "", nil, err
	}
	args = append(args, []string{
		"-x", "c", "-",
		"-o", binFile,
		"-w",
	}...)
	if data.ExtractFromELF {
		args = append(args, "-c")
	}
	cmd := osutil.Command(cc, args...)
	cmd.Stdin = src
	if out, err := cmd.CombinedOutput(); err != nil {
		os.Remove(binFile)
		return "", out, err
	}
	return binFile, nil, nil
}

func extractFromExecutable(binFile string) ([]uint64, error) {
	out, err := osutil.Command(binFile).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("failed to run flags binary: %v\n%s", err, out)
	}
	if len(out) == 0 {
		return nil, nil
	}
	var vals []uint64
	for _, val := range strings.Split(string(out), " ") {
		n, err := strconv.ParseUint(val, 10, 64)
		if err != nil {
			return nil, fmt.Errorf("failed to parse value: %v (%v)", err, val)
		}
		vals = append(vals, n)
	}
	return vals, nil
}

func extractFromELF(binFile string, targetEndian binary.ByteOrder) ([]uint64, error) {
	f, err := os.Open(binFile)
	if err != nil {
		return nil, err
	}
	ef, err := elf.NewFile(f)
	if err != nil {
		return nil, err
	}
	for _, sec := range ef.Sections {
		if sec.Name != "syz_extract_data" {
			continue
		}
		data, err := ioutil.ReadAll(sec.Open())
		if err != nil {
			return nil, err
		}
		vals := make([]uint64, len(data)/8)
		if err := binary.Read(bytes.NewReader(data), targetEndian, &vals); err != nil {
			return nil, err
		}
		return vals, nil
	}
	return nil, fmt.Errorf("did not find syz_extract_data section")
}

var srcTemplate = template.Must(template.New("").Parse(`
{{if not .ExtractFromELF}}
#define __asm__(...)
{{end}}

{{if .DefineGlibcUse}}
#ifndef __GLIBC_USE
#	define __GLIBC_USE(X) 0
#endif
{{end}}

{{range $incl := $.Includes}}
#include <{{$incl}}>
{{end}}

{{range $name, $val := $.Defines}}
#ifndef {{$name}}
#	define {{$name}} {{$val}}
#endif
{{end}}

{{.AddSource}}

{{if .DeclarePrintf}}
int printf(const char *format, ...);
{{end}}

{{if .ExtractFromELF}}
__attribute__((section("syz_extract_data")))
unsigned long long vals[] = {
	{{range $val := $.Values}}(unsigned long long){{$val}},
	{{end}}
};
{{else}}
int main() {
	int i;
	unsigned long long vals[] = {
		{{range $val := $.Values}}(unsigned long long){{$val}},
		{{end}}
	};
	for (i = 0; i < sizeof(vals)/sizeof(vals[0]); i++) {
		if (i != 0)
			printf(" ");
		printf("%llu", vals[i]);
	}
	return 0;
}
{{end}}
`))
