// Copyright 2019 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// syz-check does best-effort static correctness checking of the syscall descriptions in sys/os/*.txt.
// Use:
//	$ go install ./tools/syz-check
//	$ syz-check -obj-amd64 /linux_amd64/vmlinux -obj-arm64 /linux_arm64/vmlinux \
//		-obj-386 /linux_386/vmlinux -obj-arm /linux_arm/vmlinux
//
// The vmlinux files should include debug info, enable all relevant configs (since we parse dwarf),
// and be compiled with -fno-eliminate-unused-debug-types -fno-eliminate-unused-debug-symbols flags.
// You may check only one arch as well (but then don't commit changes to warn files):
//
//	$ syz-check -obj-amd64 /linux_amd64/vmlinux
//
// You may also disable dwarf or netlink checks with the corresponding flags.
// E.g. -dwarf=0 greatly speeds up checking if you are only interested in netlink warnings
// (but then again don't commit changes).
//
// The results are produced in sys/os/*.warn files.
// On implementation level syz-check parses vmlinux dwarf, extracts struct descriptions
// and compares them with what we have (size, fields, alignment, etc). Netlink checking extracts policy symbols
// from the object files and parses them.
package main

import (
	"bytes"
	"debug/dwarf"
	"debug/elf"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"unsafe"

	"github.com/google/syzkaller/pkg/ast"
	"github.com/google/syzkaller/pkg/cmdprof"
	"github.com/google/syzkaller/pkg/compiler"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/symbolizer"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

func main() {
	var (
		flagOS      = flag.String("os", runtime.GOOS, "OS")
		flagDWARF   = flag.Bool("dwarf", true, "do checking based on DWARF")
		flagNetlink = flag.Bool("netlink", true, "do checking of netlink policies")
	)
	arches := make(map[string]*string)
	for arch := range targets.List["linux"] {
		arches[arch] = flag.String("obj-"+arch, "", arch+" kernel object file")
	}
	failf := func(msg string, args ...interface{}) {
		fmt.Fprintf(os.Stderr, msg+"\n", args...)
		os.Exit(1)
	}
	flag.Parse()
	defer cmdprof.Install()()
	var warnings []Warn
	for arch, obj := range arches {
		if *obj == "" {
			delete(arches, arch)
			continue
		}
		warnings1, err := check(*flagOS, arch, *obj, *flagDWARF, *flagNetlink)
		if err != nil {
			failf("%v", err)
		}
		warnings = append(warnings, warnings1...)
		runtime.GC()
	}
	if len(arches) == 0 {
		fmt.Fprintf(os.Stderr, "specify at least one -obj-arch flag\n")
		flag.PrintDefaults()
		os.Exit(1)
	}
	if err := writeWarnings(*flagOS, len(arches), warnings); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func check(OS, arch, obj string, dwarf, netlink bool) ([]Warn, error) {
	var warnings []Warn
	if obj == "" {
		return nil, fmt.Errorf("no object file in -obj-%v flag", arch)
	}
	structTypes, locs, warnings1, err := parseDescriptions(OS, arch)
	if err != nil {
		return nil, err
	}
	warnings = append(warnings, warnings1...)
	if dwarf {
		structs, err := parseKernelObject(obj)
		if err != nil {
			return nil, err
		}
		warnings2, err := checkImpl(structs, structTypes, locs)
		if err != nil {
			return nil, err
		}
		warnings = append(warnings, warnings2...)
	}
	if netlink {
		warnings3, err := checkNetlink(OS, arch, obj, structTypes, locs)
		if err != nil {
			return nil, err
		}
		warnings = append(warnings, warnings3...)
	}
	for i := range warnings {
		warnings[i].arch = arch
	}
	return warnings, nil
}

const (
	WarnCompiler           = "compiler"
	WarnNoSuchStruct       = "no-such-struct"
	WarnBadStructSize      = "bad-struct-size"
	WarnBadFieldNumber     = "bad-field-number"
	WarnBadFieldSize       = "bad-field-size"
	WarnBadFieldOffset     = "bad-field-offset"
	WarnBadBitfield        = "bad-bitfield"
	WarnNoNetlinkPolicy    = "no-such-netlink-policy"
	WarnNetlinkBadSize     = "bad-kernel-netlink-policy-size"
	WarnNetlinkBadAttrType = "bad-netlink-attr-type"
	WarnNetlinkBadAttr     = "bad-netlink-attr"
)

type Warn struct {
	pos  ast.Pos
	arch string
	typ  string
	msg  string
}

func writeWarnings(OS string, narches int, warnings []Warn) error {
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
		// KVM is not supported on ARM completely.
		if OS == "linux" && warn.arch == "arm" && strings.HasSuffix(warn.pos.File, "_kvm.txt") {
			continue
		}
		byFile[warn.pos.File] = append(byFile[warn.pos.File], warn)
	}
	for file, warns := range byFile {
		sort.Slice(warns, func(i, j int) bool {
			w1, w2 := warns[i], warns[j]
			if w1.pos.Line != w2.pos.Line {
				return w1.pos.Line < w2.pos.Line
			}
			if w1.typ != w2.typ {
				return w1.typ < w2.typ
			}
			if w1.msg != w2.msg {
				return w1.msg < w2.msg
			}
			return w1.arch < w2.arch
		})
		buf := new(bytes.Buffer)
		for i := 0; i < len(warns); i++ {
			warn := warns[i]
			arch := warn.arch
			arches := []string{warn.arch}
			for i < len(warns)-1 && warn.msg == warns[i+1].msg {
				if arch != warns[i+1].arch {
					arch = warns[i+1].arch
					arches = append(arches, arch)
				}
				i++
			}
			archStr := ""
			// We do netlink checking only on amd64, so don't add arch.
			if len(arches) < narches && !strings.Contains(warn.typ, "netlink") {
				archStr = fmt.Sprintf(" [%v]", strings.Join(arches, ","))
			}
			fmt.Fprintf(buf, "%v: %v%v\n", warn.typ, warn.msg, archStr)
		}
		warnFile := file + ".warn"
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

func checkImpl(structs map[string]*dwarf.StructType, structTypes []prog.Type,
	locs map[string]*ast.Struct) ([]Warn, error) {
	var warnings []Warn
	for _, typ := range structTypes {
		name := typ.TemplateName()
		astStruct := locs[name]
		if astStruct == nil {
			continue
		}
		warns, err := checkStruct(typ, astStruct, structs[name])
		if err != nil {
			return nil, err
		}
		warnings = append(warnings, warns...)
	}
	return warnings, nil
}

func checkStruct(typ prog.Type, astStruct *ast.Struct, str *dwarf.StructType) ([]Warn, error) {
	var warnings []Warn
	warn := func(pos ast.Pos, typ, msg string, args ...interface{}) {
		warnings = append(warnings, Warn{pos: pos, typ: typ, msg: fmt.Sprintf(msg, args...)})
	}
	name := typ.TemplateName()
	if str == nil {
		// Varlen structs are frequently not described in kernel (not possible in C).
		if !typ.Varlen() {
			warn(astStruct.Pos, WarnNoSuchStruct, "%v", name)
		}
		return warnings, nil
	}
	if !typ.Varlen() && typ.Size() != uint64(str.ByteSize) {
		warn(astStruct.Pos, WarnBadStructSize, "%v: syz=%v kernel=%v", name, typ.Size(), str.ByteSize)
	}
	// TODO: handle unions, currently we should report some false errors.
	if _, ok := typ.(*prog.UnionType); ok || str.Kind == "union" {
		return warnings, nil
	}
	// TODO: we could also check enums (elements match corresponding flags in syzkaller).
	// TODO: we could also check values of literal constants (dwarf should have that, right?).
	// TODO: handle nested structs/unions, e.g.:
	// struct foo {
	//	union {
	//		...
	//	} bar;
	// };
	// should be matched with:
	// foo_bar [
	//	...
	// ]
	// TODO: consider making guesses about semantic types of fields,
	// e.g. if a name contains filedes/uid/pid/gid that may be the corresponding resource.
	ai := 0
	offset := uint64(0)
	for _, field := range typ.(*prog.StructType).Fields {
		if field.Type.Varlen() {
			ai = len(str.Field)
			break
		}
		if prog.IsPad(field.Type) {
			offset += field.Type.Size()
			continue
		}
		if ai < len(str.Field) {
			fld := str.Field[ai]
			pos := astStruct.Fields[ai].Pos
			desc := fmt.Sprintf("%v.%v", name, field.Name)
			if field.Name != fld.Name {
				desc += "/" + fld.Name
			}
			if field.Type.UnitSize() != uint64(fld.Type.Size()) {
				warn(pos, WarnBadFieldSize, "%v: syz=%v kernel=%v",
					desc, field.Type.UnitSize(), fld.Type.Size())
			}
			byteOffset := offset - field.Type.UnitOffset()
			if byteOffset != uint64(fld.ByteOffset) {
				warn(pos, WarnBadFieldOffset, "%v: syz=%v kernel=%v",
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
			if field.Type.BitfieldLength() != uint64(fld.BitSize) ||
				field.Type.BitfieldOffset() != uint64(bitOffset) {
				warn(pos, WarnBadBitfield, "%v: size/offset: syz=%v/%v kernel=%v/%v",
					desc, field.Type.BitfieldLength(), field.Type.BitfieldOffset(),
					fld.BitSize, bitOffset)
			}
		}
		ai++
		offset += field.Size()
	}
	if ai != len(str.Field) {
		warn(astStruct.Pos, WarnBadFieldNumber, "%v: syz=%v kernel=%v", name, ai, len(str.Field))
	}
	return warnings, nil
}

func parseDescriptions(OS, arch string) ([]prog.Type, map[string]*ast.Struct, []Warn, error) {
	errorBuf := new(bytes.Buffer)
	var warnings []Warn
	eh := func(pos ast.Pos, msg string) {
		warnings = append(warnings, Warn{pos: pos, typ: WarnCompiler, msg: msg})
		fmt.Fprintf(errorBuf, "%v: %v\n", pos, msg)
	}
	top := ast.ParseGlob(filepath.Join("sys", OS, "*.txt"), eh)
	if top == nil {
		return nil, nil, nil, fmt.Errorf("failed to parse txt files:\n%s", errorBuf.Bytes())
	}
	consts := compiler.DeserializeConstFile(filepath.Join("sys", OS, "*.const"), eh).Arch(arch)
	if consts == nil {
		return nil, nil, nil, fmt.Errorf("failed to parse const files:\n%s", errorBuf.Bytes())
	}
	prg := compiler.Compile(top, consts, targets.Get(OS, arch), eh)
	if prg == nil {
		return nil, nil, nil, fmt.Errorf("failed to compile descriptions:\n%s", errorBuf.Bytes())
	}
	prog.RestoreLinks(prg.Syscalls, prg.Resources, prg.Types)
	locs := make(map[string]*ast.Struct)
	for _, decl := range top.Nodes {
		switch n := decl.(type) {
		case *ast.Struct:
			locs[n.Name.Name] = n
		case *ast.TypeDef:
			if n.Struct != nil {
				locs[n.Name.Name] = n.Struct
			}
		}
	}
	var structs []prog.Type
	for _, typ := range prg.Types {
		switch typ.(type) {
		case *prog.StructType, *prog.UnionType:
			structs = append(structs, typ)
		}
	}
	return structs, locs, warnings, nil
}

// Overall idea of netlink checking.
// Currnetly we check netlink policies for common detectable mistakes.
// First, we detect what looks like a netlink policy in our descriptions
// (these are structs/unions only with nlattr/nlnext/nlnetw fields).
// Then we find corresponding symbols (offset/size) in vmlinux using nm.
// Then we read elf headers and locate where these symbols are in the rodata section.
// Then read in the symbol data, which is an array of nla_policy structs.
// These structs allow to easily figure out type/size of attributes.
// Finally we compare our descriptions with the kernel policy description.
func checkNetlink(OS, arch, obj string, structTypes []prog.Type,
	locs map[string]*ast.Struct) ([]Warn, error) {
	if arch != "amd64" {
		// Netlink policies are arch-independent (?),
		// so no need to check all arches.
		// Also our definition of nlaPolicy below is 64-bit specific.
		return nil, nil
	}
	ef, err := elf.Open(obj)
	if err != nil {
		return nil, err
	}
	rodata := ef.Section(".rodata")
	if rodata == nil {
		return nil, fmt.Errorf("object file %v does not contain .rodata section", obj)
	}
	symb := symbolizer.NewSymbolizer(targets.Get(OS, arch))
	symbols, err := symb.ReadRodataSymbols(obj)
	if err != nil {
		return nil, err
	}
	var warnings []Warn
	structMap := make(map[string]prog.Type)
	for _, typ := range structTypes {
		structMap[typ.Name()] = typ
	}
	checkedAttrs := make(map[string]*checkAttr)
	for _, typ := range structTypes {
		warnings1, err := checkNetlinkStruct(locs, symbols, rodata, structMap, checkedAttrs, typ)
		if err != nil {
			return nil, err
		}
		warnings = append(warnings, warnings1...)
	}
	warnings = append(warnings, checkMissingAttrs(checkedAttrs)...)
	return warnings, nil
}

func checkNetlinkStruct(locs map[string]*ast.Struct, symbols map[string][]symbolizer.Symbol, rodata *elf.Section,
	structMap map[string]prog.Type, checkedAttrs map[string]*checkAttr, typ prog.Type) ([]Warn, error) {
	name := typ.TemplateName()
	astStruct := locs[name]
	if astStruct == nil {
		return nil, nil
	}
	var fields []prog.Field
	switch t := typ.(type) {
	case *prog.StructType:
		fields = t.Fields
	case *prog.UnionType:
		fields = t.Fields
	}
	if !isNetlinkPolicy(fields) {
		return nil, nil
	}
	kernelName := name
	var ss []symbolizer.Symbol
	// In some cases we split a single policy into multiple ones
	// (more precise description), so try to match our foo_bar_baz
	// with kernel foo_bar and foo as well.
	for kernelName != "" {
		ss = symbols[kernelName]
		if len(ss) != 0 {
			break
		}
		underscore := strings.LastIndexByte(kernelName, '_')
		if underscore == -1 {
			break
		}
		kernelName = kernelName[:underscore]
	}
	if len(ss) == 0 {
		return []Warn{{pos: astStruct.Pos, typ: WarnNoNetlinkPolicy, msg: name}}, nil
	}
	var warnings []Warn
	var warnings1 *[]Warn
	var policy1 []nlaPolicy
	var attrs1 map[int]bool
	// We may have several symbols with the same name (they frequently have internal linking),
	// in such case we choose the one that produces fewer warnings.
	for _, symb := range ss {
		if symb.Size == 0 || symb.Size%int(unsafe.Sizeof(nlaPolicy{})) != 0 {
			warnings = append(warnings, Warn{pos: astStruct.Pos, typ: WarnNetlinkBadSize,
				msg: fmt.Sprintf("%v (%v), size %v", kernelName, name, ss[0].Size)})
			continue
		}
		binary := make([]byte, symb.Size)
		addr := symb.Addr - rodata.Addr
		if _, err := rodata.ReadAt(binary, int64(addr)); err != nil {
			return nil, fmt.Errorf("failed to read policy %v (%v) at %v: %v",
				kernelName, name, symb.Addr, err)
		}
		policy := (*[1e6]nlaPolicy)(unsafe.Pointer(&binary[0]))[:symb.Size/int(unsafe.Sizeof(nlaPolicy{}))]
		warnings2, attrs2, err := checkNetlinkPolicy(structMap, typ, fields, astStruct, policy)
		if err != nil {
			return nil, err
		}
		if warnings1 == nil || len(*warnings1) > len(warnings2) {
			warnings1 = &warnings2
			policy1 = policy
			attrs1 = attrs2
		}
	}
	if warnings1 != nil {
		warnings = append(warnings, *warnings1...)
		ca := checkedAttrs[kernelName]
		if ca == nil {
			ca = &checkAttr{
				pos:    astStruct.Pos,
				name:   name,
				policy: policy1,
				attrs:  make(map[int]bool),
			}
			checkedAttrs[kernelName] = ca
		}
		for attr := range attrs1 {
			ca.attrs[attr] = true
		}
	}
	return warnings, nil
}

type checkAttr struct {
	pos    ast.Pos
	name   string
	policy []nlaPolicy
	attrs  map[int]bool
}

func checkMissingAttrs(checkedAttrs map[string]*checkAttr) []Warn {
	// Missing attribute checking is a bit tricky because we may split a single
	// kernel policy into several policies for better precision.
	// They have different names, but map to the same kernel policy.
	// We want to report a missing attribute iff it's missing in all copies of the policy.
	var warnings []Warn
	for _, ca := range checkedAttrs {
		var missing []int
		for i, pol := range ca.policy {
			// Ignore attributes that are not described in the policy
			// (some of them are unused at all, however there are cases where
			// they are not described but used as inputs, and these are actually
			// the worst ones).
			if !ca.attrs[i] && (pol.typ != NLA_UNSPEC && pol.typ != NLA_REJECT || pol.len != 0) {
				missing = append(missing, i)
			}
		}
		// If we miss too many, there is probably something else going on.
		if len(missing) != 0 && len(missing) <= 5 {
			warnings = append(warnings, Warn{
				pos: ca.pos,
				typ: WarnNetlinkBadAttr,
				msg: fmt.Sprintf("%v: missing attributes: %v", ca.name, missing),
			})
		}
	}
	return warnings
}

func isNetlinkPolicy(fields []prog.Field) bool {
	haveAttr := false
	for _, fld := range fields {
		field := fld.Type
		if prog.IsPad(field) {
			continue
		}
		if isNlattr(field) {
			haveAttr = true
			continue
		}
		if arr, ok := field.(*prog.ArrayType); ok {
			field = arr.Elem
		}
		if field1, ok := field.(*prog.StructType); ok {
			if isNetlinkPolicy(field1.Fields) {
				continue
			}
		}
		if field1, ok := field.(*prog.UnionType); ok {
			if isNetlinkPolicy(field1.Fields) {
				continue
			}
		}
		return false
	}
	return haveAttr
}

const (
	nlattrT  = "nlattr_t"
	nlattrTT = "nlattr_tt"
)

func isNlattr(typ prog.Type) bool {
	name := typ.TemplateName()
	return name == nlattrT || name == nlattrTT
}

func checkNetlinkPolicy(structMap map[string]prog.Type, typ prog.Type, fields []prog.Field,
	astStruct *ast.Struct, policy []nlaPolicy) ([]Warn, map[int]bool, error) {
	var warnings []Warn
	warn := func(pos ast.Pos, typ, msg string, args ...interface{}) {
		warnings = append(warnings, Warn{pos: pos, typ: typ, msg: fmt.Sprintf(msg, args...)})
	}
	checked := make(map[int]bool)
	ai := 0
	for _, field := range fields {
		if prog.IsPad(field.Type) {
			continue
		}
		fld := astStruct.Fields[ai]
		ai++
		if !isNlattr(field.Type) {
			continue
		}
		ft := field.Type.(*prog.StructType)
		attr := int(ft.Fields[1].Type.(*prog.ConstType).Val)
		if attr >= len(policy) {
			warn(fld.Pos, WarnNetlinkBadAttrType, "%v.%v: type %v, kernel policy size %v",
				typ.TemplateName(), field.Name, attr, len(policy))
			continue
		}
		if checked[attr] {
			warn(fld.Pos, WarnNetlinkBadAttr, "%v.%v: duplicate attribute",
				typ.TemplateName(), field.Name)
		}
		checked[attr] = true
		w := checkNetlinkAttr(ft, policy[attr])
		if w != "" {
			warn(fld.Pos, WarnNetlinkBadAttr, "%v.%v: %v",
				typ.TemplateName(), field.Name, w)
		}
	}
	return warnings, checked, nil
}

func checkNetlinkAttr(typ *prog.StructType, policy nlaPolicy) string {
	payload := typ.Fields[2].Type
	if typ.TemplateName() == nlattrTT {
		payload = typ.Fields[4].Type
	}
	if warn := checkAttrType(typ, payload, policy); warn != "" {
		return warn
	}
	size, minSize, maxSize := attrSize(policy)
	payloadSize := minTypeSize(payload)
	if size != -1 && size != payloadSize {
		return fmt.Sprintf("bad size %v, expect %v", payloadSize, size)
	}
	if minSize != -1 && minSize > payloadSize {
		return fmt.Sprintf("bad size %v, expect min %v", payloadSize, minSize)
	}
	if maxSize != -1 && maxSize < payloadSize {
		return fmt.Sprintf("bad size %v, expect max %v", payloadSize, maxSize)
	}

	valMin, valMax, haveVal := typeMinMaxValue(payload)
	if haveVal {
		if policy.validation == NLA_VALIDATE_RANGE || policy.validation == NLA_VALIDATE_MIN {
			if int64(valMin) < int64(policy.minVal) {
				// This is a common case that occurs several times: limit on min value of 1.
				// Not worth fixing (at least not in initial batch), it just crosses out a
				// single value of 0, which we shuold test anyway.
				if !(policy.validation == NLA_VALIDATE_MIN && policy.minVal == 1) {
					return fmt.Sprintf("bad min value %v, expect %v",
						int64(valMin), policy.minVal)
				}
			}
		}
		if policy.validation == NLA_VALIDATE_RANGE || policy.validation == NLA_VALIDATE_MAX {
			if int64(valMax) > int64(policy.maxVal) {
				return fmt.Sprintf("bad max value %v, expect %v",
					int64(valMax), policy.maxVal)
			}
		}
	}
	return ""
}

func minTypeSize(typ prog.Type) int {
	if !typ.Varlen() {
		return int(typ.Size())
	}
	if str, ok := typ.(*prog.StructType); ok {
		// Some struct args has trailing arrays, but are only checked for min size.
		// Try to get some estimation for min size of this struct.
		size := 0
		for _, field := range str.Fields {
			if !field.Varlen() {
				size += int(field.Size())
			}
		}
		return size
	}
	if arr, ok := typ.(*prog.ArrayType); ok {
		if arr.Kind == prog.ArrayRangeLen && !arr.Elem.Varlen() {
			return int(arr.RangeBegin * arr.Elem.Size())
		}
	}
	return -1
}

func checkAttrType(typ *prog.StructType, payload prog.Type, policy nlaPolicy) string {
	switch policy.typ {
	case NLA_STRING, NLA_NUL_STRING:
		if _, ok := payload.(*prog.BufferType); !ok {
			return "expect string"
		}
	case NLA_NESTED:
		if typ.TemplateName() != nlattrTT || typ.Fields[3].Type.(*prog.ConstType).Val != 1 {
			return "should be nlnest"
		}
	case NLA_BITFIELD32:
		if typ.TemplateName() != nlattrT || payload.TemplateName() != "nla_bitfield32" {
			return "should be nlattr[nla_bitfield32]"
		}
	case NLA_NESTED_ARRAY:
		return "unhandled type NLA_NESTED_ARRAY"
	case NLA_REJECT:
		return "NLA_REJECT attribute will always be rejected"
	}
	return ""
}

func attrSize(policy nlaPolicy) (int, int, int) {
	switch policy.typ {
	case NLA_UNSPEC:
		if policy.len != 0 {
			return -1, int(policy.len), -1
		}
	case NLA_MIN_LEN:
		return -1, int(policy.len), -1
	case NLA_EXACT_LEN, NLA_EXACT_LEN_WARN:
		return int(policy.len), -1, -1
	case NLA_U8, NLA_S8:
		return 1, -1, -1
	case NLA_U16, NLA_S16:
		return 2, -1, -1
	case NLA_U32, NLA_S32:
		return 4, -1, -1
	case NLA_U64, NLA_S64, NLA_MSECS:
		return 8, -1, -1
	case NLA_FLAG:
		return 0, -1, -1
	case NLA_BINARY:
		if policy.len != 0 {
			return -1, -1, int(policy.len)
		}
	}
	return -1, -1, -1
}

func typeMinMaxValue(payload prog.Type) (min, max uint64, ok bool) {
	switch typ := payload.(type) {
	case *prog.ConstType:
		return typ.Val, typ.Val, true
	case *prog.IntType:
		if typ.Kind == prog.IntRange {
			return typ.RangeBegin, typ.RangeEnd, true
		}
		return 0, ^uint64(0), true
	case *prog.FlagsType:
		min, max := ^uint64(0), uint64(0)
		for _, v := range typ.Vals {
			if min > v {
				min = v
			}
			if max < v {
				max = v
			}
		}
		return min, max, true
	}
	return 0, 0, false
}

type nlaPolicy struct {
	typ        uint8
	validation uint8
	len        uint16
	_          uint32
	minVal     int16
	maxVal     int16
	_          int32
}

// nolint
const (
	NLA_UNSPEC = iota
	NLA_U8
	NLA_U16
	NLA_U32
	NLA_U64
	NLA_STRING
	NLA_FLAG
	NLA_MSECS
	NLA_NESTED
	NLA_NESTED_ARRAY
	NLA_NUL_STRING
	NLA_BINARY
	NLA_S8
	NLA_S16
	NLA_S32
	NLA_S64
	NLA_BITFIELD32
	NLA_REJECT
	NLA_EXACT_LEN
	NLA_EXACT_LEN_WARN
	NLA_MIN_LEN
)

// nolint
const (
	_ = iota
	NLA_VALIDATE_RANGE
	NLA_VALIDATE_MIN
	NLA_VALIDATE_MAX
)
