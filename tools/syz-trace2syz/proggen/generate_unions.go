// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package proggen

import (
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/tools/syz-trace2syz/parser"
)

func genSockaddrStorage(syzType *prog.UnionType, straceType parser.IrType, ctx *Context) prog.Arg {
	field2Opt := make(map[string]int)
	for i, field := range syzType.Fields {
		field2Opt[field.FieldName()] = i
	}
	// We currently look at the first argument of the system call
	// To determine which option of the union we select.
	call := ctx.CurrentStraceCall
	var straceArg parser.IrType
	switch call.CallName {
	// May need to handle special cases.
	case "recvfrom", "sendto":
		straceArg = call.Args[4]
	default:
		if len(call.Args) >= 2 {
			straceArg = call.Args[1]
		} else {
			log.Fatalf("unable identify union for sockaddr_storage for call: %s",
				call.CallName)
		}
	}
	idx := 0
	switch strType := straceArg.(type) {
	case *parser.GroupType:
		socketFamily, ok := strType.Elems[0].(parser.Constant)
		if !ok {
			log.Fatalf("failed to identify socket family when generating sockaddr stroage union. "+
				"expected constant got: %#v", strType.Elems[0])
		}
		switch socketFamily.Val() {
		case ctx.Target.ConstMap["AF_INET6"]:
			idx = field2Opt["in6"]
		case ctx.Target.ConstMap["AF_INET"]:
			idx = field2Opt["in"]
		case ctx.Target.ConstMap["AF_UNIX"]:
			idx = field2Opt["un"]
		case ctx.Target.ConstMap["AF_UNSPEC"]:
			idx = field2Opt["nl"]
		case ctx.Target.ConstMap["AF_NETLINK"]:
			idx = field2Opt["nl"]
		case ctx.Target.ConstMap["AF_NFC"]:
			idx = field2Opt["nfc"]
		case ctx.Target.ConstMap["AF_PACKET"]:
			idx = field2Opt["ll"]
		}

	default:
		log.Fatalf("unable to parse sockaddr_storage. Unsupported type: %#v", strType)
	}
	return prog.MakeUnionArg(syzType, genArgs(syzType.Fields[idx], straceType, ctx))
}

func genSockaddrNetlink(syzType *prog.UnionType, straceType parser.IrType, ctx *Context) prog.Arg {
	var idx = 2
	field2Opt := make(map[string]int)
	for i, field := range syzType.Fields {
		field2Opt[field.FieldName()] = i
	}
	switch a := ctx.CurrentStraceArg.(type) {
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
	return prog.MakeUnionArg(syzType, genArgs(syzType.Fields[idx], straceType, ctx))
}

func genIfrIfru(syzType *prog.UnionType, straceType parser.IrType, ctx *Context) prog.Arg {
	idx := 0
	switch ctx.CurrentStraceArg.(type) {
	case parser.Constant:
		idx = 2
	}
	return prog.MakeUnionArg(syzType, genArgs(syzType.Fields[idx], straceType, ctx))
}
