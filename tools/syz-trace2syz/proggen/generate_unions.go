// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build !codeanalysis

package proggen

import (
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/tools/syz-trace2syz/parser"
)

func (ctx *context) genSockaddrStorage(syzType *prog.UnionType, dir prog.Dir, straceType parser.IrType) prog.Arg {
	field2Opt := make(map[string]int)
	for i, field := range syzType.Fields {
		field2Opt[field.Name] = i
	}
	idx := 0
	switch strType := straceType.(type) {
	case *parser.GroupType:
		socketFamily, ok := strType.Elems[0].(parser.Constant)
		if !ok {
			log.Fatalf("failed to identify socket family when generating sockaddr stroage union. "+
				"expected constant got: %#v", strType.Elems[0])
		}
		switch socketFamily.Val() {
		case ctx.target.ConstMap["AF_INET6"]:
			idx = field2Opt["in6"]
		case ctx.target.ConstMap["AF_INET"]:
			idx = field2Opt["in"]
		case ctx.target.ConstMap["AF_UNIX"]:
			idx = field2Opt["un"]
		case ctx.target.ConstMap["AF_UNSPEC"]:
			idx = field2Opt["nl"]
		case ctx.target.ConstMap["AF_NETLINK"]:
			idx = field2Opt["nl"]
		case ctx.target.ConstMap["AF_NFC"]:
			idx = field2Opt["nfc"]
		case ctx.target.ConstMap["AF_PACKET"]:
			idx = field2Opt["ll"]
		}

	default:
		log.Fatalf("unable to parse sockaddr_storage. Unsupported type: %#v", strType)
	}
	return prog.MakeUnionArg(syzType, dir, ctx.genArg(syzType.Fields[idx].Type, dir, straceType), idx)
}

func (ctx *context) genSockaddrNetlink(syzType *prog.UnionType, dir prog.Dir, straceType parser.IrType) prog.Arg {
	var idx = 2
	field2Opt := make(map[string]int)
	for i, field := range syzType.Fields {
		field2Opt[field.Name] = i
	}
	switch a := straceType.(type) {
	case *parser.GroupType:
		if len(a.Elems) > 2 {
			switch b := a.Elems[1].(type) {
			case parser.Constant:
				pid := b.Val()
				if pid > 0 {
					// User
					idx = field2Opt["proc"]
				} else if pid == 0 {
					// Kernel
					idx = field2Opt["kern"]
				} else {
					// Unspec
					idx = field2Opt["unspec"]
				}
			default:
				log.Fatalf("unable to parse netlink addr struct. Unsupported type: %#v", a)
			}
		}
	}
	return prog.MakeUnionArg(syzType, dir, ctx.genArg(syzType.Fields[idx].Type, dir, straceType), idx)
}

func (ctx *context) genIfrIfru(syzType *prog.UnionType, dir prog.Dir, straceType parser.IrType) prog.Arg {
	idx := 0
	switch straceType.(type) {
	case parser.Constant:
		idx = 2
	}
	return prog.MakeUnionArg(syzType, dir, ctx.genArg(syzType.Fields[idx].Type, dir, straceType), idx)
}
