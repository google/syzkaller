// Copyright 2019 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// syz-check does best-effort static correctness checking of the syscall descriptions in sys/os/*.txt.
// Use:
//	$ go install ./tools/syz-check
//	$ syz-check -obj /linux/vmlinux
// Currently it works only for linux and only for one arch at a time.
// The vmlinux files should include debug info and enable all relevant configs (since we parse dwarf).
// The results are produced in sys/os/*.warn files.
// On implementation level syz-check parses vmlinux dwarf, extracts struct descriptions
// and compares them with what we have (size, fields, alignment, etc).
package main

import (
	"bytes"
	"debug/dwarf"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"runtime/pprof"
	"sort"

	"github.com/google/syzkaller/pkg/ast"
	"github.com/google/syzkaller/pkg/compiler"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

func main() {
	var (
		flagOS           = flag.String("os", runtime.GOOS, "OS")
		flagArch         = flag.String("arch", runtime.GOARCH, "arch")
		flagKernelObject = flag.String("obj", "", "kernel object file")
		flagCPUProfile   = flag.String("cpuprofile", "", "write CPU profile to this file")
		flagMEMProfile   = flag.String("memprofile", "", "write memory profile to this file")
	)
	flag.Parse()
	if *flagCPUProfile != "" {
		f, err := os.Create(*flagCPUProfile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to create cpuprofile file: %v\n", err)
			os.Exit(1)
		}
		defer f.Close()
		if err := pprof.StartCPUProfile(f); err != nil {
			fmt.Fprintf(os.Stderr, "failed to start cpu profile: %v\n", err)
			os.Exit(1)
		}
		defer pprof.StopCPUProfile()
	}
	if *flagMEMProfile != "" {
		defer func() {
			f, err := os.Create(*flagMEMProfile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to create memprofile file: %v\n", err)
				os.Exit(1)
			}
			defer f.Close()
			runtime.GC()
			if err := pprof.WriteHeapProfile(f); err != nil {
				fmt.Fprintf(os.Stderr, "failed to write mem profile: %v\n", err)
				os.Exit(1)
			}
		}()
	}
	if err := check(*flagOS, *flagArch, *flagKernelObject); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func check(OS, arch, obj string) error {
	structs, err := parseKernelObject(obj)
	if err != nil {
		return err
	}
	structDescs, locs, err := parseDescriptions(OS, arch)
	if err != nil {
		return err
	}
	warnings, err := checkImpl(structs, structDescs, locs)
	if err != nil {
		return err
	}
	return writeWarnings(OS, arch, warnings)
}

func writeWarnings(OS, arch string, warnings map[string][]string) error {
	allFiles, err := filepath.Glob(filepath.Join("sys", OS, "*.warn"))
	if err != nil {
		return err
	}
	toRemove := make(map[string]bool)
	for _, file := range allFiles {
		toRemove[file] = true
	}
	for file, warns := range warnings {
		sort.Strings(warns)
		buf := new(bytes.Buffer)
		for _, warn := range warns {
			fmt.Fprintf(buf, "%v\n", warn)
		}
		warnFile := filepath.Join("sys", OS, file+".warn")
		if err := osutil.WriteFile(warnFile, buf.Bytes()); err != nil {
			return err
		}
		delete(toRemove, warnFile)
	}
	for file := range toRemove {
		os.Remove(file)
	}
	return nil
}

func checkImpl(structs map[string]*dwarf.StructType, structDescs []*prog.KeyedStruct,
	locs map[string]*ast.Struct) (map[string][]string, error) {
	warnings := make(map[string][]string)
	checked := make(map[string]bool)
	for _, str := range structDescs {
		typ := str.Desc
		if typ.Varlen() {
			continue
		}
		astStruct := locs[typ.Name()]
		if astStruct == nil {
			// TODO: that's a template. Handle templates.
			continue
		}
		if checked[typ.Name()] {
			continue
		}
		checked[typ.Name()] = true

		if err := checkStruct(warnings, typ, astStruct, structs[typ.Name()]); err != nil {
			return nil, err
		}

	}
	return warnings, nil
}

func checkStruct(warnings map[string][]string, typ *prog.StructDesc, astStruct *ast.Struct,
	str *dwarf.StructType) error {
	warn := func(pos ast.Pos, msg string, args ...interface{}) {
		warnings[pos.File] = append(warnings[pos.File],
			fmt.Sprintf("%04v: ", pos.Line)+fmt.Sprintf(msg, args...))
	}
	if str == nil {
		warn(astStruct.Pos, "struct %v: no corresponding struct in kernel", typ.Name())
		return nil
	}
	if typ.Size() != uint64(str.ByteSize) {
		warn(astStruct.Pos, "struct %v: bad size: syz=%v kernel=%v", typ.Name(), typ.Size(), str.ByteSize)
	}
	// TODO: handle unions, currently we should report some false errors.
	ai := 0
	offset := uint64(0)
	for _, field := range typ.Fields {
		if prog.IsPad(field) {
			offset += field.Size()
			continue
		}
		if ai < len(str.Field) {
			fld := str.Field[ai]
			if field.Size() != uint64(fld.Type.Size()) {
				warn(astStruct.Fields[ai].Pos, "field %v.%v/%v: bad size: syz=%v kernel=%v",
					typ.Name(), field.FieldName(), fld.Name, field.Size(), fld.Type.Size())
			}
			if offset != uint64(fld.ByteOffset) {
				warn(astStruct.Fields[ai].Pos, "field %v.%v/%v: bad offset: syz=%v kernel=%v",
					typ.Name(), field.FieldName(), fld.Name, offset, fld.ByteOffset)
			}
			// How would you define bitfield offset?
			// Offset of the beginning of the field from the beginning of the memory location, right?
			// No, DWARF defines it as offset of the end of the field from the end of the memory location.
			offset := fld.Type.Size()*8 - fld.BitOffset - fld.BitSize
			if fld.BitSize == 0 {
				// And to make things even more interesting this calculation
				// does not work for normal variables.
				offset = 0
			}
			if field.BitfieldLength() != uint64(fld.BitSize) ||
				field.BitfieldOffset() != uint64(offset) {
				warn(astStruct.Fields[ai].Pos, "field %v.%v/%v: bad bit size/offset: syz=%v/%v kernel=%v/%v",
					typ.Name(), field.FieldName(), fld.Name,
					field.BitfieldLength(), field.BitfieldOffset(),
					fld.BitSize, offset)
			}
		}
		ai++
		if !field.BitfieldMiddle() {
			offset += field.Size()
		}
	}
	if ai != len(str.Field) {
		warn(astStruct.Pos, "struct %v: bad number of fields: syz=%v kernel=%v", typ.Name(), ai, len(str.Field))
	}
	return nil
}

func parseDescriptions(OS, arch string) ([]*prog.KeyedStruct, map[string]*ast.Struct, error) {
	eh := func(pos ast.Pos, msg string) {}
	top := ast.ParseGlob(filepath.Join("sys", OS, "*.txt"), eh)
	if top == nil {
		return nil, nil, fmt.Errorf("failed to parse txt files")
	}
	consts := compiler.DeserializeConstsGlob(filepath.Join("sys", OS, "*_"+arch+".const"), eh)
	if consts == nil {
		return nil, nil, fmt.Errorf("failed to parse const files")
	}
	prg := compiler.Compile(top, consts, targets.Get(OS, arch), eh)
	if prg == nil {
		return nil, nil, fmt.Errorf("failed to compile descriptions")
	}
	prog.RestoreLinks(prg.Syscalls, prg.Resources, prg.StructDescs)
	locs := make(map[string]*ast.Struct)
	for _, decl := range top.Nodes {
		switch n := decl.(type) {
		case *ast.Struct:
			locs[n.Name.Name] = n
		}
	}
	return prg.StructDescs, locs, nil
}
