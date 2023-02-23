// Copyright 2015/2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"text/template"

	"github.com/google/syzkaller/pkg/ast"
	"github.com/google/syzkaller/pkg/compiler"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/serializer"
	"github.com/google/syzkaller/pkg/tool"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

type SyscallData struct {
	Name     string
	CallName string
	NR       int32
	NeedCall bool
	Attrs    []uint64
}

type Define struct {
	Name  string
	Value string
}

type ArchData struct {
	Revision   string
	ForkServer int
	Shmem      int
	GOARCH     string
	PageSize   uint64
	NumPages   uint64
	DataOffset uint64
	Calls      []SyscallData
	Defines    []Define
}

type OSData struct {
	GOOS  string
	Archs []ArchData
}

type CallPropDescription struct {
	Type string
	Name string
}

type ExecutorData struct {
	OSes      []OSData
	CallAttrs []string
	CallProps []CallPropDescription
}

var srcDir = flag.String("src", "", "path to root of syzkaller source dir")
var outDir = flag.String("out", "", "path to out dir")

func main() {
	defer tool.Init()()

	var OSList []string
	for OS := range targets.List {
		OSList = append(OSList, OS)
	}
	sort.Strings(OSList)

	data := &ExecutorData{}
	for _, OS := range OSList {
		descriptions := ast.ParseGlob(filepath.Join(*srcDir, "sys", OS, "*.txt"), nil)
		if descriptions == nil {
			os.Exit(1)
		}
		constFile := compiler.DeserializeConstFile(filepath.Join(*srcDir, "sys", OS, "*.const"), nil)
		if constFile == nil {
			os.Exit(1)
		}
		osutil.MkdirAll(filepath.Join(*outDir, "sys", OS, "gen"))

		var archs []string
		for arch := range targets.List[OS] {
			archs = append(archs, arch)
		}
		sort.Strings(archs)

		var jobs []*Job
		for _, arch := range archs {
			jobs = append(jobs, &Job{
				Target:      targets.List[OS][arch],
				Unsupported: make(map[string]bool),
			})
		}
		sort.Slice(jobs, func(i, j int) bool {
			return jobs[i].Target.Arch < jobs[j].Target.Arch
		})
		var wg sync.WaitGroup
		wg.Add(len(jobs))

		for _, job := range jobs {
			job := job
			go func() {
				defer wg.Done()
				processJob(job, descriptions, constFile)
			}()
		}
		wg.Wait()

		var syscallArchs []ArchData
		unsupported := make(map[string]int)
		for _, job := range jobs {
			if !job.OK {
				fmt.Printf("compilation of %v/%v target failed:\n", job.Target.OS, job.Target.Arch)
				for _, msg := range job.Errors {
					fmt.Print(msg)
				}
				os.Exit(1)
			}
			syscallArchs = append(syscallArchs, job.ArchData)
			for u := range job.Unsupported {
				unsupported[u]++
			}
		}
		data.OSes = append(data.OSes, OSData{
			GOOS:  OS,
			Archs: syscallArchs,
		})

		for what, count := range unsupported {
			if count == len(jobs) {
				tool.Failf("%v is unsupported on all arches (typo?)", what)
			}
		}
	}

	attrs := reflect.TypeOf(prog.SyscallAttrs{})
	for i := 0; i < attrs.NumField(); i++ {
		data.CallAttrs = append(data.CallAttrs, prog.CppName(attrs.Field(i).Name))
	}

	props := prog.CallProps{}
	props.ForeachProp(func(name, _ string, value reflect.Value) {
		data.CallProps = append(data.CallProps, CallPropDescription{
			Type: value.Kind().String(),
			Name: prog.CppName(name),
		})
	})

	writeExecutorSyscalls(data)
}

type Job struct {
	Target      *targets.Target
	OK          bool
	Errors      []string
	Unsupported map[string]bool
	ArchData    ArchData
}

func processJob(job *Job, descriptions *ast.Description, constFile *compiler.ConstFile) {
	eh := func(pos ast.Pos, msg string) {
		job.Errors = append(job.Errors, fmt.Sprintf("%v: %v\n", pos, msg))
	}
	consts := constFile.Arch(job.Target.Arch)
	if job.Target.OS == targets.TestOS {
		constInfo := compiler.ExtractConsts(descriptions, job.Target, eh)
		compiler.FabricateSyscallConsts(job.Target, constInfo, consts)
	}
	prog := compiler.Compile(descriptions, consts, job.Target, eh)
	if prog == nil {
		return
	}
	for what := range prog.Unsupported {
		job.Unsupported[what] = true
	}

	sysFile := filepath.Join(*outDir, "sys", job.Target.OS, "gen", job.Target.Arch+".go")
	out := new(bytes.Buffer)
	generate(job.Target, prog, consts, out)
	rev := hash.String(out.Bytes())
	fmt.Fprintf(out, "const revision_%v = %q\n", job.Target.Arch, rev)
	writeSource(sysFile, out.Bytes())

	job.ArchData = generateExecutorSyscalls(job.Target, prog.Syscalls, rev)

	// Don't print warnings, they are printed in syz-check.
	job.Errors = nil
	job.OK = true
}

func generate(target *targets.Target, prg *compiler.Prog, consts map[string]uint64, out io.Writer) {
	tag := fmt.Sprintf("syz_target,syz_os_%v,syz_arch_%v", target.OS, target.Arch)
	if target.VMArch != "" {
		tag += fmt.Sprintf(" syz_target,syz_os_%v,syz_arch_%v", target.OS, target.VMArch)
	}
	fmt.Fprintf(out, "// AUTOGENERATED FILE\n")
	fmt.Fprintf(out, "// +build !codeanalysis\n")
	fmt.Fprintf(out, "// +build !syz_target %v\n\n", tag)
	fmt.Fprintf(out, "package gen\n\n")
	fmt.Fprintf(out, "import . \"github.com/google/syzkaller/prog\"\n")
	fmt.Fprintf(out, "import . \"github.com/google/syzkaller/sys/%v\"\n\n", target.OS)

	fmt.Fprintf(out, "func init() {\n")
	fmt.Fprintf(out, "\tRegisterTarget(&Target{"+
		"OS: %q, Arch: %q, Revision: revision_%v, PtrSize: %v, PageSize: %v, "+
		"NumPages: %v, DataOffset: %v, LittleEndian: %v, ExecutorUsesShmem: %v, "+
		"Syscalls: syscalls_%v, Resources: resources_%v, Consts: consts_%v}, "+
		"types_%v, InitTarget)\n}\n\n",
		target.OS, target.Arch, target.Arch, target.PtrSize, target.PageSize,
		target.NumPages, target.DataOffset, target.LittleEndian, target.ExecutorUsesShmem,
		target.Arch, target.Arch, target.Arch, target.Arch)

	fmt.Fprintf(out, "var resources_%v = ", target.Arch)
	serializer.Write(out, prg.Resources)
	fmt.Fprintf(out, "\n\n")

	fmt.Fprintf(out, "var syscalls_%v = ", target.Arch)
	serializer.Write(out, prg.Syscalls)
	fmt.Fprintf(out, "\n\n")

	fmt.Fprintf(out, "var types_%v = ", target.Arch)
	serializer.Write(out, prg.Types)
	fmt.Fprintf(out, "\n\n")

	constArr := make([]prog.ConstValue, 0, len(consts))
	for name, val := range consts {
		constArr = append(constArr, prog.ConstValue{Name: name, Value: val})
	}
	sort.Slice(constArr, func(i, j int) bool {
		return constArr[i].Name < constArr[j].Name
	})
	fmt.Fprintf(out, "var consts_%v = ", target.Arch)
	serializer.Write(out, constArr)
	fmt.Fprintf(out, "\n\n")
}

func generateExecutorSyscalls(target *targets.Target, syscalls []*prog.Syscall, rev string) ArchData {
	data := ArchData{
		Revision:   rev,
		GOARCH:     target.Arch,
		PageSize:   target.PageSize,
		NumPages:   target.NumPages,
		DataOffset: target.DataOffset,
	}
	if target.ExecutorUsesForkServer {
		data.ForkServer = 1
	}
	if target.ExecutorUsesShmem {
		data.Shmem = 1
	}
	defines := make(map[string]string)
	for _, c := range syscalls {
		var attrVals []uint64
		attrs := reflect.ValueOf(c.Attrs)
		last := -1
		for i := 0; i < attrs.NumField(); i++ {
			attr := attrs.Field(i)
			val := uint64(0)
			switch attr.Type().Kind() {
			case reflect.Bool:
				if attr.Bool() {
					val = 1
				}
			case reflect.Uint64:
				val = attr.Uint()
			default:
				panic("unsupported syscall attribute type")
			}
			attrVals = append(attrVals, val)
			if val != 0 {
				last = i
			}
		}
		data.Calls = append(data.Calls, newSyscallData(target, c, attrVals[:last+1]))
		// Some syscalls might not be present on the compiling machine, so we
		// generate definitions for them.
		if target.SyscallNumbers && !strings.HasPrefix(c.CallName, "syz_") &&
			target.NeedSyscallDefine(c.NR) {
			defines[target.SyscallPrefix+c.CallName] = fmt.Sprintf("%d", c.NR)
		}
	}
	sort.Slice(data.Calls, func(i, j int) bool {
		return data.Calls[i].Name < data.Calls[j].Name
	})
	// Get a sorted list of definitions.
	defineNames := []string{}
	for key := range defines {
		defineNames = append(defineNames, key)
	}
	sort.Strings(defineNames)
	for _, key := range defineNames {
		data.Defines = append(data.Defines, Define{key, defines[key]})
	}
	return data
}

func newSyscallData(target *targets.Target, sc *prog.Syscall, attrs []uint64) SyscallData {
	callName, patchCallName := target.SyscallTrampolines[sc.Name]
	if !patchCallName {
		callName = sc.CallName
	}
	return SyscallData{
		Name:     sc.Name,
		CallName: callName,
		NR:       int32(sc.NR),
		NeedCall: (!target.SyscallNumbers || strings.HasPrefix(sc.CallName, "syz_") || patchCallName) && !sc.Attrs.Disabled,
		Attrs:    attrs,
	}
}

func writeExecutorSyscalls(data *ExecutorData) {
	osutil.MkdirAll(filepath.Join(*outDir, "executor"))
	sort.Slice(data.OSes, func(i, j int) bool {
		return data.OSes[i].GOOS < data.OSes[j].GOOS
	})
	buf := new(bytes.Buffer)
	if err := defsTempl.Execute(buf, data); err != nil {
		tool.Failf("failed to execute defs template: %v", err)
	}
	writeFile(filepath.Join(*outDir, "executor", "defs.h"), buf.Bytes())
	buf.Reset()
	if err := syscallsTempl.Execute(buf, data); err != nil {
		tool.Failf("failed to execute syscalls template: %v", err)
	}
	writeFile(filepath.Join(*outDir, "executor", "syscalls.h"), buf.Bytes())
}

func writeSource(file string, data []byte) {
	if oldSrc, err := os.ReadFile(file); err == nil && bytes.Equal(data, oldSrc) {
		return
	}
	writeFile(file, data)
}

func writeFile(file string, data []byte) {
	outf, err := os.Create(file)
	if err != nil {
		tool.Failf("failed to create output file: %v", err)
	}
	defer outf.Close()
	outf.Write(data)
}

var defsTempl = template.Must(template.New("").Parse(`// AUTOGENERATED FILE

struct call_attrs_t { {{range $attr := $.CallAttrs}}
	uint64_t {{$attr}};{{end}}
};

struct call_props_t { {{range $attr := $.CallProps}}
	{{$attr.Type}} {{$attr.Name}};{{end}}
};

#define read_call_props_t(var, reader) { \{{range $attr := $.CallProps}}
	(var).{{$attr.Name}} = ({{$attr.Type}})(reader); \{{end}}
}

{{range $os := $.OSes}}
#if GOOS_{{$os.GOOS}}
#define GOOS "{{$os.GOOS}}"
{{range $arch := $os.Archs}}
#if GOARCH_{{$arch.GOARCH}}
#define GOARCH "{{.GOARCH}}"
#define SYZ_REVISION "{{.Revision}}"
#define SYZ_EXECUTOR_USES_FORK_SERVER {{.ForkServer}}
#define SYZ_EXECUTOR_USES_SHMEM {{.Shmem}}
#define SYZ_PAGE_SIZE {{.PageSize}}
#define SYZ_NUM_PAGES {{.NumPages}}
#define SYZ_DATA_OFFSET {{.DataOffset}}
{{range $c := $arch.Defines}}#ifndef {{$c.Name}}
#define {{$c.Name}} {{$c.Value}}
#endif
{{end}}#endif
{{end}}
#endif
{{end}}
`))

// nolint: lll
var syscallsTempl = template.Must(template.New("").Parse(`// AUTOGENERATED FILE
// clang-format off
{{range $os := $.OSes}}
#if GOOS_{{$os.GOOS}}
{{range $arch := $os.Archs}}
#if GOARCH_{{$arch.GOARCH}}
const call_t syscalls[] = {
{{range $c := $arch.Calls}}    {"{{$c.Name}}", {{$c.NR}}{{if or $c.Attrs $c.NeedCall}}, { {{- range $attr := $c.Attrs}}{{$attr}}, {{end}}}{{end}}{{if $c.NeedCall}}, (syscall_t){{$c.CallName}}{{end}}},
{{end}}};
#endif
{{end}}
#endif
{{end}}
`))
