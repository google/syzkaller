// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package declextract

import (
	"fmt"
	"strings"
)

func (ctx *context) serializeNetlink() {
	// policyQueue helps to emit policies on their first use.
	pq := &policyQueue{
		policies: make(map[string]*NetlinkPolicy),
	}
	for _, pol := range ctx.NetlinkPolicies {
		pq.policies[pol.Name] = pol
	}
	for _, fam := range ctx.NetlinkFamilies {
		if len(fam.Ops) == 0 {
			// TODO: do something for these as well. These exist for a reason.
			// Probably only send broadcast notifications (can bind and recvmsg).
			continue
		}
		id := stringIdentifier(fam.Name)
		ctx.fmt("resource genl_%v_family_id%v[int16]\n", id, autoSuffix)
		ctx.fmt("type msghdr_%v%v[CMD, POLICY] msghdr_netlink[netlink_msg_t"+
			"[genl_%v_family_id%v, genlmsghdr_t[CMD], POLICY]]\n", id, autoSuffix, id, autoSuffix)
		ctx.fmt("syz_genetlink_get_family_id%v_%v(name ptr[in, string[\"%v\"]],"+
			" fd sock_nl_generic) genl_%v_family_id%v\n\n", autoSuffix, id, fam.Name, id, autoSuffix)

		for _, op := range fam.Ops {
			policy := voidType
			if op.Policy != "" {
				policy = op.Policy + autoSuffix
				pq.policyUsed(op.Policy)
			}
			name := ctx.uniqualize("netlink op", op.Name)
			ctx.fmt("sendmsg%v_%v(fd sock_nl_generic,"+
				" msg ptr[in, msghdr_%v%v[%v, %v]], f flags[send_flags])\n",
				autoSuffix, name, id, autoSuffix, op.Name, policy)

			ctx.noteInterface(&Interface{
				Type:             IfaceNetlinkOp,
				Name:             op.Name,
				IdentifyingConst: op.Name,
				Files:            []string{fam.SourceFile},
				Func:             op.Func,
				Access:           op.Access,
				AutoDescriptions: TristateYes,
			})
		}

		for len(pq.pending) != 0 {
			pol := pq.pending[0]
			pq.pending = pq.pending[1:]
			ctx.serializeNetlinkPolicy(pol, pq)
		}
	}
}

type policyQueue struct {
	policies map[string]*NetlinkPolicy
	pending  []*NetlinkPolicy
}

func (pq *policyQueue) policyUsed(name string) {
	if pol := pq.policies[name]; pol != nil {
		delete(pq.policies, name)
		pq.pending = append(pq.pending, pol)
	}
}

func (ctx *context) serializeNetlinkPolicy(pol *NetlinkPolicy, pq *policyQueue) {
	if len(pol.Attrs) == 0 {
		ctx.fmt("type %v auto_todo\n", pol.Name+autoSuffix)
		return
	}
	ctx.fmt("%v [\n", pol.Name+autoSuffix)
	for _, attr := range pol.Attrs {
		ctx.fmt("%v %v\n", attr.Name, ctx.nlattrType(attr, pq))
	}
	ctx.fmt("] [varlen]\n")
}

func (ctx *context) nlattrType(attr *NetlinkAttr, pq *policyQueue) string {
	nlattr, typ := "nlattr", ""
	switch attr.Kind {
	case "NLA_BITFIELD32":
		// TODO: Extract values from NLA_POLICY_BITFIELD32 macro.
		typ = "int32"
	case "NLA_MSECS":
		typ = "int64"
	case "NLA_FLAG":
		typ = voidType
	case "NLA_NESTED", "NLA_NESTED_ARRAY":
		nlattr = "nlnest"
		policy := "nl_generic_attr"
		if attr.NestedPolicy != "" {
			pq.policyUsed(attr.NestedPolicy)
			policy = attr.NestedPolicy + autoSuffix
		}
		typ = fmt.Sprintf("array[%v]", policy)
		if attr.Kind == "NLA_NESTED_ARRAY" {
			typ = fmt.Sprintf("array[nlnest[0, %v]]", typ)
		}
	default:
		field := &Field{
			Name: strings.ToLower(attr.Name),
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
