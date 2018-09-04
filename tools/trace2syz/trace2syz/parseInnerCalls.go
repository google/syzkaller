package trace2syz

import (
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/prog"
)

func parseInnerCall(syzType prog.Type, traceType *call, ctx *Context) prog.Arg {
	switch traceType.CallName {
	case "htons":
		return htonsHtonl(syzType, traceType, ctx)
	case "htonl":
		return htonsHtonl(syzType, traceType, ctx)
	case "inet_addr":
		return inetAddr(syzType, traceType, ctx)
	case "inet_pton":
		return inetPton(syzType, traceType, ctx)
	case "makedev":
		return makedev(syzType, traceType, ctx)
	default:
		log.Fatalf("Inner Call: %s Unsupported", traceType.CallName)
	}
	return nil
}

func makedev(syzType prog.Type, traceType *call, ctx *Context) prog.Arg {
	var major, minor, id int64

	arg1 := traceType.Args[0].(*expression)
	arg2 := traceType.Args[1].(*expression)
	major = int64(arg1.Eval(ctx.Target))
	minor = int64(arg2.Eval(ctx.Target))

	id = ((minor & 0xff) | ((major & 0xfff) << 8) | ((minor & ^0xff) << 12) | ((major & ^0xfff) << 32))

	return prog.MakeConstArg(syzType, uint64(id))

}

func htonsHtonl(syzType prog.Type, traceType *call, ctx *Context) prog.Arg {
	if len(traceType.Args) > 1 {
		panic("Parsing Htons/Htonl...it has more than one arg.")
	}
	switch typ := syzType.(type) {
	case *prog.ProcType:
		switch a := traceType.Args[0].(type) {
		case *expression:
			val := a.Eval(ctx.Target)
			if val >= typ.ValuesPerProc {
				return prog.MakeConstArg(syzType, typ.ValuesPerProc-1)
			}
			return prog.MakeConstArg(syzType, val)
		default:
			panic("First arg of Htons/Htonl is not expression")
		}
	case *prog.ConstType, *prog.IntType, *prog.FlagsType:
		switch a := traceType.Args[0].(type) {
		case *expression:
			val := a.Eval(ctx.Target)
			return prog.MakeConstArg(syzType, val)
		default:
			panic("First arg of Htons/Htonl is not expression")
		}
	default:
		log.Fatalf("First arg of Htons/Htonl is not const Type: %s\n", syzType.Name())
	}
	return nil
}

func inetAddr(syzType prog.Type, traceType *call, ctx *Context) prog.Arg {
	unionType := syzType.(*prog.UnionType)
	var optType prog.Type
	var innerArg prog.Arg
	if len(traceType.Args) > 1 {
		panic("Parsing InetAddr...it has more than one arg.")
	}
	switch a := traceType.Args[0].(type) {
	case *ipType:
		switch a.Str {
		case "0.0.0.0":
			optType = unionType.Fields[0]
		case "127.0.0.1":
			optType = unionType.Fields[3]
		case "255.255.255.255":
			optType = unionType.Fields[6]
		default:
			optType = unionType.Fields[7]
		}
		innerArg = prog.DefaultArg(optType)
	default:
		panic("Parsing inet_addr and inner arg has non ipv4 type")
	}
	return prog.MakeUnionArg(syzType, innerArg)
}

func inetPton(syzType prog.Type, traceType *call, ctx *Context) prog.Arg {
	unionType := syzType.(*prog.UnionType)
	var optType prog.Type
	var innerArg prog.Arg
	if len(traceType.Args) != 3 {
		log.Fatalf("InetPton expects 3 args: %v.", traceType.Args)
	}
	switch a := traceType.Args[1].(type) {
	case *ipType:
		switch a.Str {
		case "::":
			optType = unionType.Fields[0]
		case "::1":
			optType = unionType.Fields[3]
		default:
			optType = unionType.Fields[0]
		}
		innerArg = prog.DefaultArg(optType)
	default:
		panic("Parsing inet_addr and inner arg has non ipv4 type")
	}
	return prog.MakeUnionArg(syzType, innerArg)
}
