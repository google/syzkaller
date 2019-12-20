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
	structDescs, locs, warnings1, err := parseDescriptions(OS, arch)
	if err != nil {
		return err
	}
	structs, err := parseKernelObject(obj)
	if err != nil {
		return err
	}
	warnings2, err := checkImpl(structs, structDescs, locs)
	if err != nil {
		return err
	}
	return writeWarnings(OS, arch, append(warnings1, warnings2...))
}

type Warn struct {
	pos ast.Pos
	msg string
}

func writeWarnings(OS, arch string, warnings []Warn) error {
	allFiles, err := filepath.Glob(filepath.Join("sys", OS, "*.warn"))
	if err != nil {
		return err
	}
	toRemove := make(map[string]bool)
	for _, file := range allFiles {
		toRemove[file] = true
	}
	byFile := make(map[string][]Warn)
	for _, warn := range warnings {
		byFile[warn.pos.File] = append(byFile[warn.pos.File], warn)
	}
	for file, warns := range byFile {
		sort.Slice(warns, func(i, j int) bool {
			w1, w2 := warns[i], warns[j]
			if w1.pos.Line != w2.pos.Line {
				return w1.pos.Line < w2.pos.Line
			}
			return w1.msg < w2.msg
		})
		buf := new(bytes.Buffer)
		for _, warn := range warns {
			fmt.Fprintf(buf, "%v\n", warn.msg)
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
	locs map[string]*ast.Struct) ([]Warn, error) {
	var warnings []Warn
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
		warns, err := checkStruct(typ, astStruct, structs[typ.Name()])
		if err != nil {
			return nil, err
		}
		warnings = append(warnings, warns...)
	}
	return warnings, nil
}

func checkStruct(typ *prog.StructDesc, astStruct *ast.Struct, str *dwarf.StructType) ([]Warn, error) {
	var warnings []Warn
	warn := func(pos ast.Pos, msg string, args ...interface{}) {
		warnings = append(warnings, Warn{pos, fmt.Sprintf(msg, args...)})
	}
	if str == nil {
		warn(astStruct.Pos, "struct %v: no corresponding struct in kernel", typ.Name())
		return warnings, nil
	}
	if typ.Size() != uint64(str.ByteSize) {
		warn(astStruct.Pos, "struct %v: bad size: syz=%v kernel=%v", typ.Name(), typ.Size(), str.ByteSize)
	}
	// TODO: handle unions, currently we should report some false errors.
	if str.Kind == "union" {
		return warnings, nil
	}
	// TODO: we could also check enums (elements match corresponding flags in syzkaller).
	// TODO: we could also check values of literal constants (dwarf should have that, right?).
	ai := 0
	offset := uint64(0)
	for _, field := range typ.Fields {
		if prog.IsPad(field) {
			offset += field.Size()
			continue
		}
		if ai < len(str.Field) {
			fld := str.Field[ai]
			pos := astStruct.Fields[ai].Pos
			desc := fmt.Sprintf("field %v.%v", typ.Name(), field.FieldName())
			if field.FieldName() != fld.Name {
				desc += "/" + fld.Name
			}
			if field.UnitSize() != uint64(fld.Type.Size()) {
				warn(pos, "%v: bad size: syz=%v kernel=%v",
					desc, field.UnitSize(), fld.Type.Size())
			}
			byteOffset := offset - field.UnitOffset()
			if byteOffset != uint64(fld.ByteOffset) {
				warn(pos, "%v: bad offset: syz=%v kernel=%v",
					desc, byteOffset, fld.ByteOffset)
			}
			// How would you define bitfield offset?
			// Offset of the beginning of the field from the beginning of the memory location, right?
			// No, DWARF defines it as offset of the end of the field from the end of the memory location.
			bitOffset := fld.Type.Size()*8 - fld.BitOffset - fld.BitSize
			if fld.BitSize == 0 {
				// And to make things even more interesting this calculation
				// does not work for normal variables.
				bitOffset = 0
			}
			if field.BitfieldLength() != uint64(fld.BitSize) ||
				field.BitfieldOffset() != uint64(bitOffset) {
				warn(pos, "%v: bad bit size/offset: syz=%v/%v kernel=%v/%v",
					desc, field.BitfieldLength(), field.BitfieldOffset(),
					fld.BitSize, bitOffset)
			}
		}
		ai++
		offset += field.Size()
	}
	if ai != len(str.Field) {
		warn(astStruct.Pos, "struct %v: bad number of fields: syz=%v kernel=%v", typ.Name(), ai, len(str.Field))
	}
	return warnings, nil
}

func parseDescriptions(OS, arch string) ([]*prog.KeyedStruct, map[string]*ast.Struct, []Warn, error) {
	errorBuf := new(bytes.Buffer)
	var warnings []Warn
	eh := func(pos ast.Pos, msg string) {
		warnings = append(warnings, Warn{pos, msg})
		fmt.Fprintf(errorBuf, "%v: %v\n", pos, msg)
	}
	top := ast.ParseGlob(filepath.Join("sys", OS, "*.txt"), eh)
	if top == nil {
		return nil, nil, nil, fmt.Errorf("failed to parse txt files:\n%s", errorBuf.Bytes())
	}
	consts := compiler.DeserializeConstsGlob(filepath.Join("sys", OS, "*_"+arch+".const"), eh)
	if consts == nil {
		return nil, nil, nil, fmt.Errorf("failed to parse const files:\n%s", errorBuf.Bytes())
	}
	prg := compiler.Compile(top, consts, targets.Get(OS, arch), eh)
	if prg == nil {
		return nil, nil, nil, fmt.Errorf("failed to compile descriptions:\n%s", errorBuf.Bytes())
	}
	prog.RestoreLinks(prg.Syscalls, prg.Resources, prg.StructDescs)
	locs := make(map[string]*ast.Struct)
	for _, decl := range top.Nodes {
		switch n := decl.(type) {
		case *ast.Struct:
			locs[n.Name.Name] = n
		}
	}
	return prg.StructDescs, locs, warnings, nil
}
