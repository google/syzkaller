// Copyright 2015/2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bufio"
	"bytes"
	"flag"
	"fmt"
	"go/format"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/pprof"
	"sort"
	"strconv"
	"strings"

	"github.com/google/syzkaller/pkg/ast"
)

var (
	flagV          = flag.Int("v", 0, "verbosity")
	flagMemProfile = flag.String("memprofile", "", "write a memory profile to the file")

	intRegExp = regexp.MustCompile("^int([0-9]+|ptr)(be)?(:[0-9]+)?$")
)

const (
	ptrSize = 8
)

func main() {
	flag.Parse()

	top, ok := ast.ParseGlob("sys/*\\.txt", nil)
	if !ok {
		os.Exit(1)
	}
	desc := astToDesc(top)

	unsupportedFlags := make(map[string]int)
	consts := make(map[string]map[string]uint64)
	for _, arch := range archs {
		logf(0, "generating %v...", arch.Name)
		consts[arch.Name] = readConsts(arch.Name)

		unsupported := make(map[string]bool)
		archFlags := make(map[string][]string)
		for f, vals := range desc.Flags {
			var archVals []string
			for _, val := range vals {
				if isIdentifier(val) {
					if v, ok := consts[arch.Name][val]; ok {
						archVals = append(archVals, fmt.Sprint(v))
					} else {
						if !unsupported[val] {
							unsupported[val] = true
							unsupportedFlags[val]++
							logf(0, "unsupported flag: %v", val)
						}
					}
				} else {
					archVals = append(archVals, val)
				}
			}
			archFlags[f] = archVals
		}

		sysFile := filepath.Join("sys", "sys_"+arch.Name+".go")
		logf(1, "Generate code to init system call data in %v", sysFile)
		out := new(bytes.Buffer)
		archDesc := *desc
		archDesc.Flags = archFlags
		generate(arch.Name, &archDesc, consts[arch.Name], out)
		writeSource(sysFile, out.Bytes())
		logf(0, "")
	}

	for flag, count := range unsupportedFlags {
		if count == len(archs) {
			failf("flag %v is unsupported on all arches (typo?)", flag)
		}
	}

	generateExecutorSyscalls(desc.Syscalls, consts)

	if *flagMemProfile != "" {
		f, err := os.Create(*flagMemProfile)
		if err != nil {
			failf("could not create memory profile: ", err)
		}
		runtime.GC() // get up-to-date statistics
		if err := pprof.WriteHeapProfile(f); err != nil {
			failf("could not write memory profile: ", err)
		}
		f.Close()
	}
}

type Description struct {
	Syscalls  []Syscall
	Structs   map[string]*Struct
	Unnamed   map[string][]string
	Flags     map[string][]string
	StrFlags  map[string][]string
	Resources map[string]Resource
}

type Syscall struct {
	Name     string
	CallName string
	Args     [][]string
	Ret      []string
}

type Struct struct {
	Name    string
	Flds    [][]string
	IsUnion bool
	Packed  bool
	Varlen  bool
	Align   int
}

type Resource struct {
	Name   string
	Base   string
	Values []string
}

type syscallArray []Syscall

func (a syscallArray) Len() int           { return len(a) }
func (a syscallArray) Less(i, j int) bool { return a[i].Name < a[j].Name }
func (a syscallArray) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }

func astToDesc(top []interface{}) *Description {
	// As a temporal measure we just convert the new representation to the old one.
	// TODO: check for duplicate defines, structs, resources.
	// TODO: check for duplicate syscall argument names.
	desc := &Description{
		Structs:   make(map[string]*Struct),
		Unnamed:   make(map[string][]string),
		Flags:     make(map[string][]string),
		StrFlags:  make(map[string][]string),
		Resources: make(map[string]Resource),
	}
	unnamedSeq := 0
	for _, decl := range top {
		switch n := decl.(type) {
		case *ast.Resource:
			var vals []string
			for _, v := range n.Values {
				switch {
				case v.Ident != "":
					vals = append(vals, v.Ident)
				default:
					if v.ValueHex {
						vals = append(vals, fmt.Sprintf("0x%x", uintptr(v.Value)))
					} else {
						vals = append(vals, fmt.Sprint(uintptr(v.Value)))
					}
				}
			}
			desc.Resources[n.Name.Name] = Resource{
				Name:   n.Name.Name,
				Base:   n.Base.Name,
				Values: vals,
			}
		case *ast.Call:
			call := Syscall{
				Name:     n.Name.Name,
				CallName: n.CallName,
			}
			for _, a := range n.Args {
				call.Args = append(call.Args, astToDescField(a, desc.Unnamed, &unnamedSeq))
			}
			if n.Ret != nil {
				call.Ret = astToDescType(n.Ret, desc.Unnamed, &unnamedSeq)
			}
			desc.Syscalls = append(desc.Syscalls, call)
		case *ast.Struct:
			str := &Struct{
				Name:    n.Name.Name,
				IsUnion: n.IsUnion,
			}
			for _, f := range n.Fields {
				str.Flds = append(str.Flds, astToDescField(f, desc.Unnamed, &unnamedSeq))
			}
			if n.IsUnion {
				for _, attr := range n.Attrs {
					switch attr.Name {
					case "varlen":
						str.Varlen = true
					default:
						failf("unknown union %v attribute: %v", str.Name, attr.Name)
					}
				}
			} else {
				for _, attr := range n.Attrs {
					switch {
					case attr.Name == "packed":
						str.Packed = true
					case attr.Name == "align_ptr":
						str.Align = 8 // TODO: this must be target pointer size
					case strings.HasPrefix(attr.Name, "align_"):
						a, err := strconv.ParseUint(attr.Name[6:], 10, 64)
						if err != nil {
							failf("bad struct %v alignment %v: %v", str.Name, attr.Name, err)
						}
						if a&(a-1) != 0 || a == 0 || a > 1<<30 {
							failf("bad struct %v alignment %v: must be sane power of 2", str.Name, a)
						}
						str.Align = int(a)
					default:
						failf("unknown struct %v attribute: %v", str.Name, attr.Name)
					}
				}
			}
			if str.IsUnion && len(str.Flds) <= 1 {
				failf("union %v has only %v fields, need at least 2", str.Name, len(str.Flds))
			}
			fields := make(map[string]bool)
			for _, f := range str.Flds {
				if f[0] == "parent" {
					failf("struct/union %v contains reserved field 'parent'", str.Name)
				}
				if fields[f[0]] {
					failf("duplicate field %v in struct/union %v", f[0], str.Name)
				}
				fields[f[0]] = true
			}
			desc.Structs[str.Name] = str
		case *ast.IntFlags:
			var vals []string
			for _, v := range n.Values {
				switch {
				case v.Ident != "":
					vals = append(vals, v.Ident)
				default:
					if v.ValueHex {
						vals = append(vals, fmt.Sprintf("0x%x", uintptr(v.Value)))
					} else {
						vals = append(vals, fmt.Sprint(uintptr(v.Value)))
					}
				}
			}
			desc.Flags[n.Name.Name] = vals
		case *ast.StrFlags:
			var vals []string
			for _, v := range n.Values {
				vals = append(vals, v.Value)
			}
			desc.StrFlags[n.Name.Name] = vals
		}
	}
	sort.Sort(syscallArray(desc.Syscalls))
	return desc
}

func astToDescField(n *ast.Field, unnamed map[string][]string, unnamedSeq *int) []string {
	return append([]string{n.Name.Name}, astToDescType(n.Type, unnamed, unnamedSeq)...)
}

func astToDescType(n *ast.Type, unnamed map[string][]string, unnamedSeq *int) []string {
	res := []string{astTypeToStr(n)}
	for _, t := range n.Args {
		if len(t.Args) == 0 {
			res = append(res, astTypeToStr(t))
			continue
		}
		id := fmt.Sprintf("unnamed%v", *unnamedSeq)
		(*unnamedSeq)++
		unnamed[id] = astToDescType(t, unnamed, unnamedSeq)
		res = append(res, id)
	}
	return res
}

func astTypeToStr(n *ast.Type) string {
	res := ""
	switch {
	case n.Ident != "":
		res = n.Ident
	case n.String != "":
		res = fmt.Sprintf("\"%v\"", n.String)
	default:
		if n.ValueHex {
			res = fmt.Sprintf("0x%x", uintptr(n.Value))
		} else {
			res = fmt.Sprint(uintptr(n.Value))
		}
	}
	if n.Ident2 != "" {
		res += ":" + n.Ident2
	} else if n.Value2 != 0 {
		if n.Value2Hex {
			res += fmt.Sprintf(":0x%x", uintptr(n.Value2))
		} else {
			res += ":" + fmt.Sprint(uintptr(n.Value2))
		}
	}
	return res
}

func readConsts(arch string) map[string]uint64 {
	constFiles, err := filepath.Glob("sys/*_" + arch + ".const")
	if err != nil {
		failf("failed to find const files: %v", err)
	}
	consts := make(map[string]uint64)
	for _, fname := range constFiles {
		f, err := os.Open(fname)
		if err != nil {
			failf("failed to open const file: %v", err)
		}
		defer f.Close()
		s := bufio.NewScanner(f)
		for s.Scan() {
			line := s.Text()
			if line == "" || line[0] == '#' {
				continue
			}
			eq := strings.IndexByte(line, '=')
			if eq == -1 {
				failf("malformed const file %v: no '=' in '%v'", fname, line)
			}
			name := strings.TrimSpace(line[:eq])
			val, err := strconv.ParseUint(strings.TrimSpace(line[eq+1:]), 0, 64)
			if err != nil {
				failf("malformed const file %v: bad value in '%v'", fname, line)
			}
			if old, ok := consts[name]; ok && old != val {
				failf("const %v has different values for %v: %v vs %v", name, arch, old, val)
			}
			consts[name] = val
		}
		if err := s.Err(); err != nil {
			failf("failed to read const file: %v", err)
		}
	}
	for name, nr := range syzkalls {
		consts["__NR_"+name] = nr
	}
	return consts
}

var skipCurrentSyscall string

func skipSyscall(why string) {
	if skipCurrentSyscall != "" {
		skipCurrentSyscall = why
	}
}

func generate(arch string, desc *Description, consts map[string]uint64, out io.Writer) {
	unsupported := make(map[string]bool)

	fmt.Fprintf(out, "// AUTOGENERATED FILE\n")
	fmt.Fprintf(out, "package sys\n\n")

	generateResources(desc, consts, out)
	generateStructs(desc, consts, out)

	fmt.Fprintf(out, "var Calls = []*Call{\n")
	for _, s := range desc.Syscalls {
		logf(4, "    generate population code for %v", s.Name)
		skipCurrentSyscall = ""
		syscallNR := -1
		if nr, ok := consts["__NR_"+s.CallName]; ok {
			syscallNR = int(nr)
		} else {
			if !unsupported[s.CallName] {
				unsupported[s.CallName] = true
				logf(0, "unsupported syscall: %v", s.CallName)
			}
		}
		native := true
		if _, ok := syzkalls[s.CallName]; ok {
			native = false
		}
		fmt.Fprintf(out, "&Call{Name: \"%v\", CallName: \"%v\", Native: %v", s.Name, s.CallName, native)
		if len(s.Ret) != 0 {
			fmt.Fprintf(out, ", Ret: ")
			generateArg("", "ret", s.Ret[0], "out", s.Ret[1:], desc, consts, true, false, out)
		}
		fmt.Fprintf(out, ", Args: []Type{")
		for i, a := range s.Args {
			if i != 0 {
				fmt.Fprintf(out, ", ")
			}
			logf(5, "      generate description for arg %v", i)
			generateArg("", a[0], a[1], "in", a[2:], desc, consts, true, false, out)
		}
		if skipCurrentSyscall != "" {
			logf(0, "unsupported syscall: %v due to %v", s.Name, skipCurrentSyscall)
			syscallNR = -1
		}
		fmt.Fprintf(out, "}, NR: %v},\n", syscallNR)
	}
	fmt.Fprintf(out, "}\n\n")

	var constArr []NameValue
	for name, val := range consts {
		constArr = append(constArr, NameValue{name, val})
	}
	sort.Sort(NameValueArray(constArr))

	fmt.Fprintf(out, "const (\n")
	for _, nv := range constArr {
		fmt.Fprintf(out, "%v = %v\n", nv.name, nv.val)
	}
	fmt.Fprintf(out, ")\n")
}

func generateResources(desc *Description, consts map[string]uint64, out io.Writer) {
	var resArray ResourceArray
	for _, res := range desc.Resources {
		resArray = append(resArray, res)
	}
	sort.Sort(resArray)

	fmt.Fprintf(out, "var resourceArray = []*ResourceDesc{\n")
	for _, res := range resArray {
		underlying := ""
		name := res.Name
		kind := []string{name}
		var values []string
	loop:
		for {
			var values1 []string
			for _, v := range res.Values {
				if v1, ok := consts[v]; ok {
					values1 = append(values1, fmt.Sprint(v1))
				} else if !isIdentifier(v) {
					values1 = append(values1, v)
				}
			}
			values = append(values1, values...)
			switch res.Base {
			case "int8", "int16", "int32", "int64", "intptr":
				underlying = res.Base
				break loop
			default:
				if _, ok := desc.Resources[res.Base]; !ok {
					failf("resource '%v' has unknown parent resource '%v'", name, res.Base)
				}
				kind = append([]string{res.Base}, kind...)
				res = desc.Resources[res.Base]
			}
		}
		fmt.Fprintf(out, "&ResourceDesc{Name: \"%v\", Type: ", name)
		generateArg("", "resource-type", underlying, "inout", nil, desc, consts, true, true, out)
		fmt.Fprintf(out, ", Kind: []string{")
		for i, k := range kind {
			if i != 0 {
				fmt.Fprintf(out, ", ")
			}
			fmt.Fprintf(out, "\"%v\"", k)
		}
		fmt.Fprintf(out, "}, Values: []uint64{")
		if len(values) == 0 {
			values = append(values, "0")
		}
		for i, v := range values {
			if i != 0 {
				fmt.Fprintf(out, ", ")
			}
			fmt.Fprintf(out, "%v", v)
		}
		fmt.Fprintf(out, "}},\n")
	}
	fmt.Fprintf(out, "}\n")
}

type structKey struct {
	name  string
	field string
	dir   string
}

func generateStructEntry(str *Struct, out io.Writer) {
	typ := "StructType"
	if str.IsUnion {
		typ = "UnionType"
	}
	packed := ""
	if str.Packed {
		packed = ", packed: true"
	}
	varlen := ""
	if str.Varlen {
		varlen = ", varlen: true"
	}
	align := ""
	if str.Align != 0 {
		align = fmt.Sprintf(", align: %v", str.Align)
	}
	fmt.Fprintf(out, "&%v{TypeCommon: TypeCommon{TypeName: \"%v\", IsOptional: %v} %v %v %v},\n",
		typ, str.Name, false, packed, align, varlen)
}

func generateStructFields(str *Struct, key structKey, desc *Description, consts map[string]uint64, out io.Writer) {
	fmt.Fprintf(out, "{structKey{\"%v\", \"%v\", %v}, []Type{\n", key.name, key.field, fmtDir(key.dir))
	for _, a := range str.Flds {
		generateArg(str.Name, a[0], a[1], key.dir, a[2:], desc, consts, false, true, out)
		fmt.Fprintf(out, ",\n")
	}
	fmt.Fprintf(out, "}},\n")

}

func generateStructs(desc *Description, consts map[string]uint64, out io.Writer) {
	// Struct fields can refer to other structs. Go compiler won't like if
	// we refer to Structs during Structs initialization. So we do
	// it in 2 passes: on the first pass create struct types without fields,
	// on the second pass we fill in fields.

	// Since structs of the same type can be fields with different names
	// of multiple other structs, we have an instance of those structs
	// for each field indexed by the name of the parent struct, field name and dir.

	structMap := make(map[structKey]*Struct)
	for _, str := range desc.Structs {
		for _, dir := range []string{"in", "out", "inout"} {
			structMap[structKey{str.Name, "", dir}] = str
		}
		for _, a := range str.Flds {
			if innerStr, ok := desc.Structs[a[1]]; ok {
				for _, dir := range []string{"in", "out", "inout"} {
					structMap[structKey{a[1], a[0], dir}] = innerStr
				}
			}
		}
	}

	fmt.Fprintf(out, "var structArray = []Type{\n")
	sortedStructs := make([]*Struct, 0, len(desc.Structs))
	for _, str := range desc.Structs {
		sortedStructs = append(sortedStructs, str)
	}
	sort.Sort(structSorter(sortedStructs))
	for _, str := range sortedStructs {
		generateStructEntry(str, out)
	}
	fmt.Fprintf(out, "}\n")

	fmt.Fprintf(out, "var structFields = []struct{key structKey; fields []Type}{")
	sortedKeys := make([]structKey, 0, len(structMap))
	for key := range structMap {
		sortedKeys = append(sortedKeys, key)
	}
	sort.Sort(structKeySorter(sortedKeys))
	for _, key := range sortedKeys {
		generateStructFields(structMap[key], key, desc, consts, out)
	}
	fmt.Fprintf(out, "}\n")
}

func parseRange(buffer string, consts map[string]uint64) (string, string) {
	lookupConst := func(name string) string {
		if v, ok := consts[name]; ok {
			return fmt.Sprint(v)
		}
		return name
	}

	parts := strings.Split(buffer, ":")
	switch len(parts) {
	case 1:
		v := lookupConst(buffer)
		return v, v
	case 2:
		return lookupConst(parts[0]), lookupConst(parts[1])
	default:
		failf("bad range: %v", buffer)
		return "", ""
	}
}

func generateArg(
	parent, name, typ, dir string,
	a []string,
	desc *Description,
	consts map[string]uint64,
	isArg, isField bool,
	out io.Writer) {
	origName := name
	name = "\"" + name + "\""
	opt := false
	for i, v := range a {
		if v == "opt" {
			opt = true
			copy(a[i:], a[i+1:])
			a = a[:len(a)-1]
			break
		}
	}
	fmtDir(dir) // Make sure that dir is "in", "out" or "inout"
	common := func() string {
		return fmt.Sprintf("TypeCommon: TypeCommon{TypeName: \"%v\", FldName: %v, ArgDir: %v, IsOptional: %v}", typ, name, fmtDir(dir), opt)
	}
	intCommon := func(typeSize uint64, bigEndian bool, bitfieldLen uint64) string {
		// BitfieldOff and BitfieldLst will be filled in in initAlign().
		return fmt.Sprintf("IntTypeCommon: IntTypeCommon{%v, TypeSize: %v, BigEndian: %v, BitfieldLen: %v}", common(), typeSize, bigEndian, bitfieldLen)
	}
	canBeArg := false
	switch typ {
	case "fileoff":
		canBeArg = true
		size := uint64(ptrSize)
		bigEndian := false
		bitfieldLen := uint64(0)
		if isField {
			if want := 1; len(a) != want {
				failf("wrong number of arguments for %v arg %v, want %v, got %v", typ, name, want, len(a))
			}
			size, bigEndian, bitfieldLen = decodeIntType(a[0])
		} else {
			if want := 0; len(a) != want {
				failf("wrong number of arguments for %v arg %v, want %v, got %v", typ, name, want, len(a))
			}
		}
		fmt.Fprintf(out, "&IntType{%v, Kind: IntFileoff}", intCommon(size, bigEndian, bitfieldLen))
	case "buffer":
		canBeArg = true
		if want := 1; len(a) != want {
			failf("wrong number of arguments for %v arg %v, want %v, got %v", typ, name, want, len(a))
		}
		ptrCommonHdr := common()
		dir = a[0]
		opt = false
		fmt.Fprintf(out, "&PtrType{%v, Type: &BufferType{%v, Kind: BufferBlobRand}}", ptrCommonHdr, common())
	case "string":
		if len(a) != 0 && len(a) != 1 && len(a) != 2 {
			failf("wrong number of arguments for %v arg %v, want 0-2, got %v", typ, name, len(a))
		}
		var vals []string
		subkind := ""
		if len(a) >= 1 {
			if a[0][0] == '"' {
				vals = append(vals, a[0][1:len(a[0])-1])
			} else {
				vals1, ok := desc.StrFlags[a[0]]
				if !ok {
					failf("unknown string flags %v", a[0])
				}
				vals = append([]string{}, vals1...)
				subkind = a[0]
			}
		}
		for i, s := range vals {
			vals[i] = s + "\x00"
		}
		var size uint64
		if len(a) >= 2 {
			if v, ok := consts[a[1]]; ok {
				size = v
			} else {
				v, err := strconv.ParseUint(a[1], 10, 64)
				if err != nil {
					failf("failed to parse string length for %v", name, a[1])
				}
				size = v
			}
			for i, s := range vals {
				if uint64(len(s)) > size {
					failf("string value %q exceeds buffer length %v for arg %v", s, size, name)
				}
				for uint64(len(s)) < size {
					s += "\x00"
				}
				vals[i] = s
			}
		} else {
			for _, s := range vals {
				if size != 0 && size != uint64(len(s)) {
					size = 0
					break
				}
				size = uint64(len(s))
			}
		}
		fmt.Fprintf(out, "&BufferType{%v, Kind: BufferString, SubKind: %q, Values: %#v, Length: %v}", common(), subkind, vals, size)
	case "salg_type":
		if want := 0; len(a) != want {
			failf("wrong number of arguments for %v arg %v, want %v, got %v", typ, name, want, len(a))
		}
		fmt.Fprintf(out, "&BufferType{%v, Kind: BufferAlgType}", common())
	case "salg_name":
		if want := 0; len(a) != want {
			failf("wrong number of arguments for %v arg %v, want %v, got %v", typ, name, want, len(a))
		}
		fmt.Fprintf(out, "&BufferType{%v, Kind: BufferAlgName}", common())
	case "vma":
		canBeArg = true
		begin, end := "0", "0"
		switch len(a) {
		case 0:
		case 1:
			begin, end = parseRange(a[0], consts)
		default:
			failf("wrong number of arguments for %v arg %v, want 0 or 1, got %v", typ, name, len(a))
		}
		fmt.Fprintf(out, "&VmaType{%v, RangeBegin: %v, RangeEnd: %v}", common(), begin, end)
	case "len", "bytesize", "bytesize2", "bytesize4", "bytesize8":
		canBeArg = true
		size := uint64(ptrSize)
		bigEndian := false
		bitfieldLen := uint64(0)
		if isField {
			if want := 2; len(a) != want {
				failf("wrong number of arguments for %v arg %v, want %v, got %v", typ, name, want, len(a))
			}
			size, bigEndian, bitfieldLen = decodeIntType(a[1])
		} else {
			if want := 1; len(a) != want {
				failf("wrong number of arguments for %v arg %v, want %v, got %v", typ, name, want, len(a))
			}
		}
		byteSize := uint8(0)
		if typ != "len" {
			byteSize = decodeByteSizeType(typ)
		}
		fmt.Fprintf(out, "&LenType{%v, Buf: \"%v\", ByteSize: %v}", intCommon(size, bigEndian, bitfieldLen), a[0], byteSize)
	case "csum":
		if len(a) != 3 && len(a) != 4 {
			failf("wrong number of arguments for %v arg %v, want 3-4, got %v", typ, name, len(a))
		}
		var size uint64
		var bigEndian bool
		var bitfieldLen uint64
		var protocol uint64
		var kind string
		switch a[1] {
		case "inet":
			kind = "CsumInet"
			size, bigEndian, bitfieldLen = decodeIntType(a[2])
		case "pseudo":
			kind = "CsumPseudo"
			size, bigEndian, bitfieldLen = decodeIntType(a[3])
			if v, ok := consts[a[2]]; ok {
				protocol = v
			} else {
				v, err := strconv.ParseUint(a[2], 10, 64)
				if err != nil {
					failf("failed to parse protocol %v", a[2])
				}
				protocol = v
			}
		default:
			failf("unknown checksum kind '%v'", a[0])
		}
		fmt.Fprintf(out, "&CsumType{%v, Buf: \"%s\", Kind: %v, Protocol: %v}", intCommon(size, bigEndian, bitfieldLen), a[0], kind, protocol)
	case "flags":
		canBeArg = true
		size := uint64(ptrSize)
		bigEndian := false
		bitfieldLen := uint64(0)
		if isField {
			if want := 2; len(a) != want {
				failf("wrong number of arguments for %v arg %v, want %v, got %v", typ, name, want, len(a))
			}
			size, bigEndian, bitfieldLen = decodeIntType(a[1])
		} else {
			if want := 1; len(a) != want {
				failf("wrong number of arguments for %v arg %v, want %v, got %v", typ, name, want, len(a))
			}
		}
		vals, ok := desc.Flags[a[0]]
		if !ok {
			failf("unknown flag %v", a[0])
		}
		if len(vals) == 0 {
			fmt.Fprintf(out, "&IntType{%v}", intCommon(size, bigEndian, bitfieldLen))
		} else {
			fmt.Fprintf(out, "&FlagsType{%v, Vals: []uint64{%v}}", intCommon(size, bigEndian, bitfieldLen), strings.Join(vals, ","))
		}
	case "const":
		canBeArg = true
		size := uint64(ptrSize)
		bigEndian := false
		bitfieldLen := uint64(0)
		if isField {
			if want := 2; len(a) != want {
				failf("wrong number of arguments for %v arg %v, want %v, got %v", typ, name, want, len(a))
			}
			size, bigEndian, bitfieldLen = decodeIntType(a[1])
		} else {
			if want := 1; len(a) != want {
				failf("wrong number of arguments for %v arg %v, want %v, got %v", typ, name, want, len(a))
			}
		}
		val := a[0]
		if v, ok := consts[a[0]]; ok {
			val = fmt.Sprint(v)
		} else if isIdentifier(a[0]) {
			// This is an identifier for which we don't have a value for this arch.
			// Skip this syscall on this arch.
			val = "0"
			skipSyscall(fmt.Sprintf("missing const %v", a[0]))
		}
		fmt.Fprintf(out, "&ConstType{%v, Val: uint64(%v)}", intCommon(size, bigEndian, bitfieldLen), val)
	case "proc":
		canBeArg = true
		size := uint64(ptrSize)
		bigEndian := false
		bitfieldLen := uint64(0)
		var valuesStart string
		var valuesPerProc string
		if isField {
			if want := 3; len(a) != want {
				failf("wrong number of arguments for %v arg %v, want %v, got %v", typ, name, want, len(a))
			}
			size, bigEndian, bitfieldLen = decodeIntType(a[0])
			valuesStart = a[1]
			valuesPerProc = a[2]
		} else {
			if want := 2; len(a) != want {
				failf("wrong number of arguments for %v arg %v, want %v, got %v", typ, name, want, len(a))
			}
			valuesStart = a[0]
			valuesPerProc = a[1]
		}
		valuesStartInt, err := strconv.ParseInt(valuesStart, 10, 64)
		if err != nil {
			failf("couldn't parse '%v' as int64", valuesStart)
		}
		valuesPerProcInt, err := strconv.ParseInt(valuesPerProc, 10, 64)
		if err != nil {
			failf("couldn't parse '%v' as int64", valuesPerProc)
		}
		if valuesPerProcInt < 1 {
			failf("values per proc '%v' should be >= 1", valuesPerProcInt)
		}
		if size != 8 && valuesStartInt >= (1<<(size*8)) {
			failf("values starting from '%v' overflow desired type of size '%v'", valuesStartInt, size)
		}
		const maxPids = 32 // executor knows about this constant (MAX_PIDS)
		if size != 8 && valuesStartInt+maxPids*valuesPerProcInt >= (1<<(size*8)) {
			failf("not enough values starting from '%v' with step '%v' and type size '%v' for 32 procs", valuesStartInt, valuesPerProcInt, size)
		}
		fmt.Fprintf(out, "&ProcType{%v, ValuesStart: %v, ValuesPerProc: %v}", intCommon(size, bigEndian, bitfieldLen), valuesStartInt, valuesPerProcInt)
	case "signalno":
		canBeArg = true
		if want := 0; len(a) != want {
			failf("wrong number of arguments for %v arg %v, want %v, got %v", typ, name, want, len(a))
		}
		fmt.Fprintf(out, "&IntType{%v, Kind: IntSignalno}", intCommon(4, false, 0))
	case "filename":
		if want := 0; len(a) != want {
			failf("wrong number of arguments for %v arg %v, want %v, got %v", typ, name, want, len(a))
		}
		fmt.Fprintf(out, "&BufferType{%v, Kind: BufferFilename}", common())
	case "text":
		if want := 1; len(a) != want {
			failf("wrong number of arguments for %v arg %v, want %v, got %v", typ, name, want, len(a))
		}
		kind := ""
		switch a[0] {
		case "x86_real", "x86_16", "x86_32", "x86_64", "arm64":
			kind = "Text_" + a[0]
		default:
			failf("unknown text type %v for %v arg %v", a[0], typ, name)
		}
		fmt.Fprintf(out, "&BufferType{%v, Kind: BufferText, Text: %v}", common(), kind)
	case "array":
		if len(a) != 1 && len(a) != 2 {
			failf("wrong number of arguments for %v arg %v, want 1 or 2, got %v", typ, name, len(a))
		}
		if len(a) == 1 {
			if a[0] == "int8" {
				fmt.Fprintf(out, "&BufferType{%v, Kind: BufferBlobRand}", common())
			} else {
				fmt.Fprintf(out, "&ArrayType{%v, Type: %v, Kind: ArrayRandLen}", common(), generateType(a[0], dir, desc, consts))
			}
		} else {
			begin, end := parseRange(a[1], consts)
			if a[0] == "int8" {
				fmt.Fprintf(out, "&BufferType{%v, Kind: BufferBlobRange, RangeBegin: %v, RangeEnd: %v}", common(), begin, end)
			} else {
				fmt.Fprintf(out, "&ArrayType{%v, Type: %v, Kind: ArrayRangeLen, RangeBegin: %v, RangeEnd: %v}", common(), generateType(a[0], dir, desc, consts), begin, end)
			}
		}
	case "ptr":
		canBeArg = true
		if want := 2; len(a) != want {
			failf("wrong number of arguments for %v arg %v, want %v, got %v", typ, name, want, len(a))
		}
		dir = "in"
		fmt.Fprintf(out, "&PtrType{%v, Type: %v}", common(), generateType(a[1], a[0], desc, consts))
	default:
		if intRegExp.MatchString(typ) {
			canBeArg = true
			size, bigEndian, bitfieldLen := decodeIntType(typ)
			switch len(a) {
			case 0:
				fmt.Fprintf(out, "&IntType{%v}", intCommon(size, bigEndian, bitfieldLen))
			case 1:
				begin, end := parseRange(a[0], consts)
				fmt.Fprintf(out, "&IntType{%v, Kind: IntRange, RangeBegin: %v, RangeEnd: %v}",
					intCommon(size, bigEndian, bitfieldLen), begin, end)
			default:
				failf("wrong number of arguments for %v arg %v, want 0 or 1, got %v", typ, name, len(a))
			}
		} else if strings.HasPrefix(typ, "unnamed") {
			if inner, ok := desc.Unnamed[typ]; ok {
				generateArg("", "", inner[0], dir, inner[1:], desc, consts, false, isField, out)
			} else {
				failf("unknown unnamed type '%v'", typ)
			}
		} else if _, ok := desc.Structs[typ]; ok {
			if len(a) != 0 {
				failf("struct '%v' has args", typ)
			}
			fmt.Fprintf(out, "getStruct(structKey{\"%v\", \"%v\", %v})", typ, origName, fmtDir(dir))
		} else if _, ok := desc.Resources[typ]; ok {
			if len(a) != 0 {
				failf("resource '%v' has args", typ)
			}
			fmt.Fprintf(out, "&ResourceType{%v, Desc: resource(\"%v\")}", common(), typ)
			return
		} else {
			failf("unknown arg type \"%v\" for %v", typ, name)
		}
	}
	if isArg && !canBeArg {
		failf("%v %v can't be syscall argument/return", name, typ)
	}
}

func generateType(typ, dir string, desc *Description, consts map[string]uint64) string {
	buf := new(bytes.Buffer)
	generateArg("", "", typ, dir, nil, desc, consts, false, true, buf)
	return buf.String()
}

func fmtDir(s string) string {
	switch s {
	case "in":
		return "DirIn"
	case "out":
		return "DirOut"
	case "inout":
		return "DirInOut"
	default:
		failf("bad direction %v", s)
		return ""
	}
}

func decodeIntType(typ string) (uint64, bool, uint64) {
	bigEndian := false
	bitfieldLen := uint64(0)

	parts := strings.Split(typ, ":")
	if len(parts) == 2 {
		var err error
		bitfieldLen, err = strconv.ParseUint(parts[1], 10, 64)
		if err != nil {
			failf("failed to parse bitfield length '%v'", parts[1])
		}
		typ = parts[0]
	}

	if strings.HasSuffix(typ, "be") {
		bigEndian = true
		typ = typ[:len(typ)-2]
	}

	switch typ {
	case "int8", "int16", "int32", "int64", "intptr":
	default:
		failf("unknown type %v", typ)
	}
	sz := int64(ptrSize * 8)
	if typ != "intptr" {
		sz, _ = strconv.ParseInt(typ[3:], 10, 64)
	}

	if bitfieldLen > uint64(sz) {
		failf("bitfield of size %v is too large for base type of size %v", bitfieldLen, sz/8)
	}

	return uint64(sz / 8), bigEndian, bitfieldLen
}

func decodeByteSizeType(typ string) uint8 {
	switch typ {
	case "bytesize", "bytesize2", "bytesize4", "bytesize8":
	default:
		failf("unknown type %v", typ)
	}
	sz := int64(1)
	if typ != "bytesize" {
		sz, _ = strconv.ParseInt(typ[8:], 10, 8)
	}
	return uint8(sz)
}

func isIdentifier(s string) bool {
	for i, c := range s {
		if c == '_' || (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || i > 0 && (c >= '0' && c <= '9') {
			continue
		}
		return false
	}
	return true
}

func writeSource(file string, data []byte) {
	src, err := format.Source(data)
	if err != nil {
		fmt.Printf("%s\n", data)
		failf("failed to format output: %v", err)
	}
	if oldSrc, err := ioutil.ReadFile(file); err == nil && bytes.Equal(src, oldSrc) {
		return
	}
	writeFile(file, src)
}

func writeFile(file string, data []byte) {
	outf, err := os.Create(file)
	if err != nil {
		failf("failed to create output file: %v", err)
	}
	defer outf.Close()
	outf.Write(data)
}

type NameValue struct {
	name string
	val  uint64
}

type NameValueArray []NameValue

func (a NameValueArray) Len() int           { return len(a) }
func (a NameValueArray) Less(i, j int) bool { return a[i].name < a[j].name }
func (a NameValueArray) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }

type ResourceArray []Resource

func (a ResourceArray) Len() int           { return len(a) }
func (a ResourceArray) Less(i, j int) bool { return a[i].Name < a[j].Name }
func (a ResourceArray) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }

type structSorter []*Struct

func (a structSorter) Len() int           { return len(a) }
func (a structSorter) Less(i, j int) bool { return a[i].Name < a[j].Name }
func (a structSorter) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }

type structKeySorter []structKey

func (a structKeySorter) Len() int { return len(a) }
func (a structKeySorter) Less(i, j int) bool {
	if a[i].name < a[j].name {
		return true
	}
	if a[i].name > a[j].name {
		return false
	}
	if a[i].field < a[j].field {
		return true
	}
	if a[i].field > a[j].field {
		return false
	}
	return a[i].dir < a[j].dir
}
func (a structKeySorter) Swap(i, j int) { a[i], a[j] = a[j], a[i] }

func failf(msg string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, msg+"\n", args...)
	os.Exit(1)
}

func logf(v int, msg string, args ...interface{}) {
	if *flagV >= v {
		fmt.Fprintf(os.Stderr, msg+"\n", args...)
	}
}
