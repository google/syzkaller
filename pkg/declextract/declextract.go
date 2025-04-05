// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package declextract

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/google/syzkaller/pkg/ifaceprobe"
)

type Result struct {
	Descriptions []byte
	Interfaces   []*Interface
	IncludeUse   map[string]string
	StructInfo   map[string]*StructInfo
}

type StructInfo struct {
	Size  int
	Align int
}

func Run(out *Output, probe *ifaceprobe.Info, syscallRename map[string][]string, trace io.Writer) (
	*Result, error) {
	ctx := &context{
		Output:        out,
		probe:         probe,
		syscallRename: syscallRename,
		structs:       make(map[string]*Struct),
		funcs:         make(map[string]*Function),
		ioctls:        make(map[string]*Type),
		facts:         make(map[string]*typingNode),
		uniqualizer:   make(map[string]int),
		debugTrace:    trace,
	}
	ctx.processFunctions()
	ctx.processTypingFacts()
	includeUse := ctx.processConsts()
	ctx.processEnums()
	structInfo := ctx.processStructs()
	ctx.processSyscalls()
	ctx.processIouring()

	ctx.serialize()
	ctx.finishInterfaces()
	if len(ctx.errs) != 0 {
		return nil, errors.Join(ctx.errs...)
	}
	return &Result{
		Descriptions: ctx.descriptions.Bytes(),
		Interfaces:   ctx.interfaces,
		IncludeUse:   includeUse,
		StructInfo:   structInfo,
	}, nil
}

type context struct {
	*Output
	probe         *ifaceprobe.Info
	syscallRename map[string][]string // syscall function -> syscall names
	structs       map[string]*Struct
	funcs         map[string]*Function
	ioctls        map[string]*Type
	facts         map[string]*typingNode
	includes      []string
	defines       []define
	uniqualizer   map[string]int
	interfaces    []*Interface
	descriptions  *bytes.Buffer
	debugTrace    io.Writer
	errs          []error
}

type define struct {
	Name  string
	Value string
}

func (ctx *context) error(msg string, args ...any) {
	ctx.errs = append(ctx.errs, fmt.Errorf(msg, args...))
}

func (ctx *context) warn(msg string, args ...any) {
	fmt.Fprintf(os.Stderr, msg+"\n", args...)
}

func (ctx *context) trace(msg string, args ...any) {
	if ctx.debugTrace != nil {
		fmt.Fprintf(ctx.debugTrace, msg+"\n", args...)
	}
}

func (ctx *context) processConsts() map[string]string {
	replaces := map[string]string{
		// Arches may use some includes from asm-generic and some from arch/arm.
		// If the arch used for extract used asm-generic for a header,
		// other arches may need arch/asm version of the header. So switch to
		// a more generic file name that should resolve correctly for all arches.
		"include/uapi/asm-generic/ioctls.h":  "asm/ioctls.h",
		"include/uapi/asm-generic/sockios.h": "asm/sockios.h",
	}
	defineDedup := make(map[string]bool)
	includeUse := make(map[string]string)
	for _, ci := range ctx.Consts {
		if strings.Contains(ci.Filename, "/uapi/") && !strings.Contains(ci.Filename, "arch/x86/") &&
			strings.HasSuffix(ci.Filename, ".h") {
			filename := ci.Filename
			if replace := replaces[filename]; replace != "" {
				filename = replace
			}
			ctx.includes = append(ctx.includes, filename)
			includeUse[ci.Name] = filename
			continue
		}
		// Remove duplicate defines (even with different values). Unfortunately we get few of these.
		// There are some syscall numbers (presumably for 32/64 bits), and some macros that
		// are defined in different files to different values (e.g. WMI_DATA_BE_SVC).
		// Ideally we somehow rename defines (chosing one random value is never correct).
		// But for now this helps to prevent compilation errors.
		if defineDedup[ci.Name] {
			continue
		}
		defineDedup[ci.Name] = true
		ctx.defines = append(ctx.defines, define{
			Name:  ci.Name,
			Value: fmt.Sprint(ci.Value),
		})
	}
	ctx.includes = sortAndDedupSlice(ctx.includes)
	ctx.defines = sortAndDedupSlice(ctx.defines)
	// These additional includes must be at the top, because other kernel headers
	// are broken and won't compile without these additional ones included first.
	ctx.includes = append([]string{
		"vdso/bits.h",
		"linux/types.h",
		"linux/usbdevice_fs.h", // to fix broken include/uapi/linux/usbdevice_fs.h
		"net/netlink.h",
	}, ctx.includes...)
	// Also pretend they are used.
	includeUse["__NR_read"] = "vdso/bits.h"
	includeUse["__NR_write"] = "linux/types.h"
	includeUse["__NR_openat"] = "linux/usbdevice_fs.h"
	includeUse["__NR_close"] = "net/netlink.h"
	return includeUse
}

func (ctx *context) processEnums() {
	for _, enum := range ctx.Enums {
		enum.Name += autoSuffix
	}
}

func (ctx *context) processSyscalls() {
	var syscalls []*Syscall
	for _, call := range ctx.Syscalls {
		ctx.processFields(call.Args, "", false)
		call.returnType = ctx.inferReturnType(call.Func, call.SourceFile)
		for i, arg := range call.Args {
			typ := ctx.inferArgType(call.Func, call.SourceFile, i)
			refineFieldType(arg, typ, false)
		}
		ctx.emitSyscall(&syscalls, call, "")
		for i := range call.Args {
			cmds := ctx.inferCommandVariants(call.Func, call.SourceFile, i)
			for _, cmd := range cmds {
				variant := *call
				variant.Args = slices.Clone(call.Args)
				newArg := *variant.Args[i]
				newArg.syzType = fmt.Sprintf("const[%v]", cmd)
				variant.Args[i] = &newArg
				suffix := cmd
				if call.Func == "__do_sys_ioctl" {
					suffix = ctx.uniqualize("ioctl cmd", cmd)
				}
				ctx.emitSyscall(&syscalls, &variant, "_"+suffix)
			}
		}
	}
	ctx.Syscalls = sortAndDedupSlice(syscalls)
}

func (ctx *context) emitSyscall(syscalls *[]*Syscall, call *Syscall, suffix string) {
	fn := strings.TrimPrefix(call.Func, "__do_sys_")
	for _, name := range ctx.syscallRename[fn] {
		ctx.noteInterface(&Interface{
			Type:             IfaceSyscall,
			Name:             name,
			IdentifyingConst: "__NR_" + name,
			Files:            []string{call.SourceFile},
			Func:             call.Func,
			AutoDescriptions: true,
		})
		newCall := *call
		newCall.Func = name + autoSuffix + suffix
		*syscalls = append(*syscalls, &newCall)
	}
}

func (ctx *context) processIouring() {
	for _, op := range ctx.IouringOps {
		ctx.noteInterface(&Interface{
			Type:             IfaceIouring,
			Name:             op.Name,
			IdentifyingConst: op.Name,
			Files:            []string{op.SourceFile},
			Func:             op.Func,
			Access:           AccessUser,
		})
	}
}

func (ctx *context) processStructs() map[string]*StructInfo {
	structInfo := make(map[string]*StructInfo)
	for _, str := range ctx.Structs {
		str.Name += autoSuffix
		ctx.structs[str.Name] = str
		structInfo[str.Name] = &StructInfo{
			Size:  str.ByteSize,
			Align: str.Align,
		}
	}
	for _, str := range ctx.Structs {
		ctx.processFields(str.Fields, str.Name, true)
		name := strings.TrimSuffix(str.Name, autoSuffix)
		for _, f := range str.Fields {
			typ := ctx.inferFieldType(name, f.Name)
			refineFieldType(f, typ, true)
		}
	}
	return structInfo
}

func (ctx *context) processFields(fields []*Field, parent string, needBase bool) {
	counts := make([]*Field, len(fields))
	for _, f := range fields {
		f.Name = fixIdentifier(f.Name)
		if f.CountedBy != -1 {
			counts[f.CountedBy] = f
		}
	}
	for i, f := range fields {
		f.syzType = ctx.fieldType(f, counts[i], parent, needBase)
	}
}

func (ctx *context) fieldType(f, counts *Field, parent string, needBase bool) string {
	if f.BitWidth != 0 && !needBase {
		ctx.error("syscall arg %v is a bitfield", f.Name)
	}
	if f.BitWidth != 0 && f.Type.Int == nil {
		ctx.error("non-int field %v is a bitfield", f.Name)
	}
	if counts != nil && f.Type.Int == nil && f.Type.Ptr == nil {
		ctx.error("non-int/ptr field %v counts field %v", f.Name, counts.Name)
	}
	f.Name = strings.ToLower(f.Name)
	switch {
	case f.Type.Int != nil:
		return ctx.fieldTypeInt(f, counts, needBase)
	case f.Type.Ptr != nil:
		return ctx.fieldTypePtr(f, counts, parent)
	case f.Type.Array != nil:
		return ctx.fieldTypeArray(f, parent)
	case f.Type.Buffer != nil:
		return ctx.fieldTypeBuffer(f)
	case f.Type.Struct != "":
		return ctx.fieldTypeStruct(f)
	}
	ctx.error("field %v does not have type", f.Name)
	return ""
}

func (ctx *context) fieldTypeInt(f, counts *Field, needBase bool) string {
	t := f.Type.Int
	switch t.ByteSize {
	case 1, 2, 4, 8:
	default:
		ctx.error("field %v has unsupported size %v", f.Name, t.ByteSize)
	}
	if t.Enum != "" && counts != nil {
		ctx.error("field %v is both enum %v and counts field %v", f.Name, t.Enum, counts.Name)
	}
	baseType, isIntptr := ctx.baseIntType(f, needBase)
	constType := fmt.Sprintf("const[%v %v]", t.MinValue, maybeBaseType(baseType, needBase))
	if f.IsAnonymous || t.IsConst {
		return constType
	}
	if t.Enum != "" {
		t.Enum += autoSuffix
		return fmt.Sprintf("flags[%v %v]", t.Enum, maybeBaseType(baseType, needBase))
	}
	if counts != nil {
		return fmt.Sprintf("len[%v %v]", counts.Name, maybeBaseType(baseType, needBase))
	}
	if t.Name == "TODO" {
		return todoType
	}
	special := ""
	switch t.ByteSize {
	case 2:
		special = ctx.specialInt2(f.Name, t.Name, needBase)
	case 4:
		special = ctx.specialInt4(f.Name, t.Name, needBase)
	case 8:
		if isIntptr {
			special = ctx.specialIntptr(f.Name, t.Name, needBase)
		}
	}
	if special != "" {
		if f.BitWidth != 0 {
			// We don't have syntax to express this.
			ctx.error("field %v is both special %v and a bitfield", f.Name, special)
		}
		return special
	}
	if strings.HasSuffix(f.Name, "enabled") || strings.HasSuffix(f.Name, "enable") {
		return "bool" + strings.TrimPrefix(baseType, "int")
	}
	if strings.Contains(f.Name, "pad") || strings.Contains(f.Name, "unused") ||
		strings.Contains(f.Name, "_reserved") {
		return constType
	}
	if t.MinValue != 0 || t.MaxValue != 0 {
		minVal, maxVal := uint64(t.MinValue), uint64(t.MaxValue)
		if minVal > maxVal {
			minVal, maxVal = maxVal, minVal
		}
		return baseType + fmt.Sprintf("[%v:%v]", minVal, maxVal)
	}
	return baseType
}

func (ctx *context) baseIntType(f *Field, needBase bool) (string, bool) {
	t := f.Type.Int
	baseType := fmt.Sprintf("int%v", t.ByteSize*8)
	// Note: we make all 8-byte syscall arguments intptr b/c for 64-bit arches it does not matter,
	// but for 32-bit arches int64 as syscall argument won't work. IIUC the ABI is that these
	// are split into 2 32-bit arguments.
	isIntptr := t.ByteSize == 8 && (!needBase || strings.Contains(t.Base, "long") &&
		!strings.Contains(t.Base, "long long"))
	if isIntptr {
		baseType = "intptr"
	}
	if t.isBigEndian && t.ByteSize != 1 {
		baseType += "be"
	}
	if f.BitWidth == t.ByteSize*8 {
		f.BitWidth = 0
	}
	if f.BitWidth != 0 {
		baseType += fmt.Sprintf(":%v", f.BitWidth)
	}
	return baseType, isIntptr
}

func (ctx *context) specialInt2(field, typ string, needBase bool) string {
	switch {
	case strings.Contains(field, "port"):
		return "sock_port"
	}
	return ""
}

// nolint: gocyclo
func (ctx *context) specialInt4(field, typ string, needBase bool) string {
	switch {
	case strings.Contains(field, "ipv4") || strings.Contains(field, "ip4") ||
		strings.HasSuffix(field, "address"):
		return "ipv4_addr"
	case strings.HasSuffix(field, "_pid") || strings.HasSuffix(field, "_tid") ||
		strings.HasSuffix(field, "_pgid") || strings.HasSuffix(field, "_tgid") ||
		field == "pid" || field == "tid" || field == "pgid" || field == "tgid":
		return "pid"
	case strings.HasSuffix(field, "dfd") && !strings.HasSuffix(field, "oldfd") && !strings.HasSuffix(field, "pidfd"):
		return "fd_dir"
	case strings.HasSuffix(field, "ns_fd"):
		return "fd_namespace"
	case strings.HasSuffix(field, "_uid") || field == "uid" || field == "user" ||
		field == "ruid" || field == "euid" || field == "suid":
		return "uid"
	case strings.HasSuffix(field, "_gid") || field == "gid" || field == "group" ||
		field == "rgid" || field == "egid" || field == "sgid":
		return "gid"
	case strings.HasSuffix(field, "fd") || strings.HasPrefix(field, "fd_") ||
		strings.Contains(field, "fildes") || field == "fdin" || field == "fdout":
		return "fd"
	case strings.Contains(field, "ifindex") || strings.Contains(field, "dev_index"):
		return "ifindex"
	}
	return ""
}

func (ctx *context) specialIntptr(field, typ string, needBase bool) string {
	switch {
	case field == "sigsetsize":
		return fmt.Sprintf("const[8 %v]", maybeBaseType("intptr", needBase))
	}
	return ""
}

func (ctx *context) fieldTypePtr(f, counts *Field, parent string) string {
	t := f.Type.Ptr
	dir := "inout"
	if t.IsConst {
		dir = "in"
	}
	opt := ""
	// Use an opt pointer if the direct parent is the same as this node, or if the field name is next.
	// Looking at the field name is a hack, but it's enough to avoid some recursion cases,
	// e.g. for struct adf_user_cfg_section.
	if f.Name == "next" || parent != "" && parent == t.Elem.Struct+autoSuffix {
		opt = ", opt"
	}
	elem := &Field{
		Name: f.Name,
		Type: t.Elem,
	}
	return fmt.Sprintf("ptr[%v, %v %v]", dir, ctx.fieldType(elem, counts, parent, true), opt)
}

func (ctx *context) fieldTypeArray(f *Field, parent string) string {
	t := f.Type.Array
	elem := &Field{
		Name: f.Name,
		Type: t.Elem,
	}
	elemType := ctx.fieldType(elem, nil, parent, true)
	if t.IsConstSize {
		switch t.MaxSize {
		case 0:
			// Empty arrays may still affect parent struct layout, if the element type
			// has alignment >1. We don't support arrays of size 0, so emit a special
			// aligning type instead.
			return fmt.Sprintf("auto_aligner[%v]", t.Align)
		case 1:
			// Array of size 1 is not really an array, just use the element type itself.
			return elemType
		}
	}
	bounds := ctx.bounds(f.Name, t.MinSize, t.MaxSize)
	return fmt.Sprintf("array[%v%v]", elemType, bounds)
}

func (ctx *context) fieldTypeBuffer(f *Field) string {
	t := f.Type.Buffer
	bounds := ctx.bounds(f.Name, t.MinSize, t.MaxSize)
	baseType := "string"
	if t.IsNonTerminated {
		baseType = "stringnoz"
	}
	switch {
	case !t.IsString:
		if t.MinSize == 6 && t.MaxSize == 6 {
			// There are lots of different names for mac addresses (see grep ETH_ALEN in uapi/*.h).
			// If this has too many false positives, theoretically we can make the clang tool
			// look for arrays with [ETH_ALEN] size. See implementation of isExpandedFromMacro
			// matcher for inspiration, that would need to be checked against
			// ConstantArrayType::getSizeExpr. But for now let's just do the simple thing.
			return "mac_addr"
		}
		if (t.MaxSize == 0 || t.MaxSize == 16) &&
			(strings.Contains(f.Name, "ipv6") || strings.Contains(f.Name, "ip6")) {
			return "ipv6_addr"
		}
		return fmt.Sprintf("array[int8 %v]", bounds)
	case strings.Contains(f.Name, "ifname") || strings.HasSuffix(f.Name, "dev_name") ||
		strings.Contains(f.Name, "_iface"):
		return "devname"
	case strings.Contains(f.Name, "filename") || strings.Contains(f.Name, "pathname") ||
		strings.Contains(f.Name, "dir_name") || f.Name == "oldname" ||
		f.Name == "newname" || f.Name == "path":
		if !t.IsNonTerminated && bounds == "" {
			return "filename" // alias that is easier to read
		}
		return fmt.Sprintf("%v[filename %v]", baseType, bounds)
	}
	return baseType
}

func (ctx *context) fieldTypeStruct(f *Field) string {
	// Few important structs for which we have lots of heuristics,
	// and the static analysis will have hard time generating something of similar
	switch f.Type.Struct {
	case "in_addr":
		return "ipv4_addr"
	case "in6_addr":
		return "ipv6_addr"
	case "sockaddr":
		return "sockaddr"
	case "__kernel_sockaddr_storage":
		return "sockaddr_storage"
	}
	// We can get here several times for the same struct.
	if !strings.HasSuffix(f.Type.Struct, autoSuffix) {
		f.Type.Struct += autoSuffix
	}
	str := ctx.structs[f.Type.Struct]
	if str == nil {
		panic(fmt.Sprintf("can't find struct %v", f.Type.Struct))
	}
	if str.ByteSize == 0 {
		return fmt.Sprintf("auto_aligner[%v]", str.Align)
	}
	return f.Type.Struct
}

func (ctx *context) bounds(name string, min, max int) string {
	if min < 0 || min > max {
		ctx.error("field %v has bad bounds %v:%v", name, min, max)
	}
	if max > min {
		return fmt.Sprintf(", %v:%v", min, max)
	}
	if max != 0 {
		return fmt.Sprintf(", %v", max)
	}
	return ""
}

func (ctx *context) uniqualize(typ, name string) string {
	id := fmt.Sprintf("%v-%v", typ, name)
	ctx.uniqualizer[id]++
	if seq := ctx.uniqualizer[id]; seq != 1 {
		return name + fmt.Sprint(seq)
	}
	return name
}

const (
	autoSuffix = "$auto"
	todoType   = "auto_todo"
	voidType   = "void"
)

func fixIdentifier(name string) string {
	switch name {
	case "resource", "include", "define", "incdir", "syscall", "parent":
		return "_" + name
	}
	return name
}

func stringIdentifier(name string) string {
	for _, bad := range []string{" ", ".", "-"} {
		name = strings.ReplaceAll(name, bad, "_")
	}
	return strings.ToLower(name)
}

func maybeBaseType(baseType string, needBase bool) string {
	if needBase {
		return ", " + baseType
	}
	return ""
}

func comma(i int) string {
	if i == 0 {
		return ""
	}
	return ", "
}
