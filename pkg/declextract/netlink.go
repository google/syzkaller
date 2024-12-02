// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package declextract

import (
	"fmt"
	"sort"
	"strings"
)

func (ctx *context) fabricateNetlinkPolicies() {
	for _, pol := range ctx.NetlinkPolicies {
		if len(pol.Attrs) == 0 {
			continue
		}
		str := &Struct{
			Name:     pol.Name + autoSuffix,
			IsUnion:  true,
			isVarlen: true,
		}
		for _, attr := range pol.Attrs {
			str.Fields = append(str.Fields, &Field{
				Name:    attr.Name,
				syzType: ctx.nlattrType(attr),
			})
		}
		ctx.Structs = append(ctx.Structs, str)
	}
	ctx.Structs = sortAndDedupSlice(ctx.Structs)
}

func (ctx *context) emitNetlinkTypes() {
	for _, fam := range ctx.NetlinkFamilies {
		if isEmptyFamily(fam) {
			continue
		}
		id := stringIdentifier(fam.Name)
		ctx.fmt("resource genl_%v_family_id%v[int16]\n", id, autoSuffix)
	}
	for _, fam := range ctx.NetlinkFamilies {
		if isEmptyFamily(fam) {
			continue
		}
		id := stringIdentifier(fam.Name)
		ctx.fmt("type msghdr_%v%v[CMD, POLICY] msghdr_netlink[netlink_msg_t"+
			"[genl_%v_family_id%v, genlmsghdr_t[CMD], POLICY]]\n", id, autoSuffix, id, autoSuffix)
	}
	for _, pol := range ctx.NetlinkPolicies {
		if len(pol.Attrs) == 0 {
			ctx.fmt("type %v auto_todo\n", pol.Name+autoSuffix)
		}
	}
}

func (ctx *context) emitNetlinkGetFamily() {
	for _, fam := range ctx.NetlinkFamilies {
		if isEmptyFamily(fam) {
			continue
		}
		id := stringIdentifier(fam.Name)
		ctx.fmt("syz_genetlink_get_family_id%v_%v(name ptr[in, string[\"%v\"]],"+
			" fd sock_nl_generic) genl_%v_family_id%v\n", autoSuffix, id, fam.Name, id, autoSuffix)
	}
}

func (ctx *context) emitNetlinkSendmsgs() {
	var syscalls []string
	for _, fam := range ctx.NetlinkFamilies {
		id := stringIdentifier(fam.Name)
		dedup := make(map[string]bool)
		for _, op := range fam.Ops {
			// TODO: emit these as well, these are dump commands w/o input arguments.
			if op.Policy == "" {
				continue
			}
			// TODO: emit all of these with unique names, these should be doit/dump variants.
			// They may have different policies.
			if dedup[op.Name] {
				continue
			}
			dedup[op.Name] = true
			syscalls = append(syscalls, fmt.Sprintf("sendmsg%v_%v(fd sock_nl_generic,"+
				" msg ptr[in, msghdr_%v%v[%v, %v]], f flags[send_flags])\n",
				autoSuffix, op.Name, id, autoSuffix, op.Name, op.Policy+autoSuffix))

			ctx.noteInterface(&Interface{
				Type:             IfaceNetlinkOp,
				Name:             op.Name,
				IdentifyingConst: op.Name,
				Files:            []string{fam.SourceFile},
				Func:             op.Func,
				Access:           op.Access,
				AutoDescriptions: true,
			})
		}
	}
	sort.Strings(syscalls)
	for _, call := range syscalls {
		ctx.fmt("%s", call)
	}
}

func isEmptyFamily(fam *NetlinkFamily) bool {
	for _, op := range fam.Ops {
		if op.Policy != "" {
			return false
		}
	}
	return true
}

func (ctx *context) nlattrType(attr *NetlinkAttr) string {
	nlattr, typ := "nlattr", ""
	switch attr.Kind {
	case "NLA_BITFIELD32":
		// TODO: Extract values from NLA_POLICY_BITFIELD32 macro.
		typ = "int32"
	case "NLA_MSECS":
		typ = "int64"
	case "NLA_FLAG":
		typ = "void"
	case "NLA_NESTED", "NLA_NESTED_ARRAY":
		nlattr = "nlnest"
		policy := "nl_generic_attr"
		if attr.NestedPolicy != "" {
			policy = attr.NestedPolicy + autoSuffix
		}
		typ = fmt.Sprintf("array[%v]", policy)
		if attr.Kind == "NLA_NESTED_ARRAY" {
			typ = fmt.Sprintf("array[nlnest[0, %v]]", typ)
		}
	case "NLA_BINARY", "NLA_UNSPEC", "":
		// TODO: also handle size 6 for MAC addresses.
		if attr.Elem == nil && (attr.MaxSize == 16 || attr.MaxSize == 0) &&
			strings.Contains(attr.Name, "IPV6") {
			typ = "ipv6_addr"
			break
		}
		fallthrough
	default:
		field := &Field{
			Name: attr.Name,
			Type: ctx.netlinkType(attr),
		}
		typ = ctx.fieldType(field, nil, "", true)
	}
	return fmt.Sprintf("%v[%v, %v]", nlattr, attr.Name, typ)
}

func (ctx *context) netlinkType(attr *NetlinkAttr) *Type {
	switch attr.Kind {
	case "NLA_STRING", "NLA_NUL_STRING":
		return &Type{
			Buffer: &BufferType{
				MaxSize:         attr.MaxSize,
				IsString:        true,
				IsNonTerminated: attr.Kind == "NLA_STRING",
			},
		}
	case "NLA_BINARY", "NLA_UNSPEC", "":
		if attr.Elem == nil {
			switch attr.MaxSize {
			case 1, 2, 4, 8:
				attr.Kind = fmt.Sprintf("NLA_U%v", attr.MaxSize*8)
				return ctx.netlinkTypeInt(attr)
			}
			minSize := 0
			if attr.Kind != "NLA_BINARY" {
				minSize = attr.MaxSize
			}
			return &Type{
				Buffer: &BufferType{
					MaxSize: attr.MaxSize,
					MinSize: minSize,
				},
			}
		}
		elemSize := 1
		switch {
		case attr.Elem.Int != nil:
			elemSize = attr.Elem.Int.ByteSize
		case attr.Elem.Struct != "":
			if str := ctx.structs[attr.Elem.Struct+autoSuffix]; str != nil {
				elemSize = str.ByteSize
			} else {
				ctx.error("binary nlattr %v referenced non-existing struct %v",
					attr.Name, attr.Elem.Struct)
			}
		default:
			ctx.error("binary nlattr %v has unsupported elem type", attr.Name)
		}
		if attr.MaxSize%elemSize != 0 {
			ctx.error("binary nlattr %v has odd size: %v, elem size %v",
				attr.Name, attr.MaxSize, elemSize)
		}
		numElems := attr.MaxSize / elemSize
		if numElems == 1 {
			return attr.Elem
		}
		return &Type{
			Array: &ArrayType{
				Elem:    attr.Elem,
				MaxSize: numElems,
			},
		}
	default:
		return ctx.netlinkTypeInt(attr)
	}
}

func (ctx *context) netlinkTypeInt(attr *NetlinkAttr) *Type {
	size, be := 0, false
	switch attr.Kind {
	case "NLA_U8", "NLA_S8":
		size = 1
	case "NLA_U16", "NLA_S16":
		size = 2
	case "NLA_U32", "NLA_S32":
		size = 4
	case "NLA_U64", "NLA_S64", "NLA_SINT", "NLA_UINT":
		size = 8
	case "NLA_BE16":
		size, be = 2, true
	case "NLA_BE32":
		size, be = 4, true
	default:
		panic(fmt.Sprintf("unhandled netlink attribute kind %v", attr.Kind))
	}
	return &Type{
		Int: &IntType{
			ByteSize:    size,
			isBigEndian: be,
		},
	}
}
