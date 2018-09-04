package trace2syz

import (
	"github.com/google/syzkaller/prog"
)

type structHandler func(syzType *prog.StructType, traceType irType, ctx *Context) irType

var specialStructMap = map[string]structHandler{
	"bpf_framed_program": bpfFramedProgramHandler,
}

func preprocessStruct(syzType *prog.StructType, traceType irType, ctx *Context) irType {
	if structFunc, ok := specialStructMap[syzType.Name()]; ok {
		return structFunc(syzType, traceType, ctx)
	}
	return traceType
}

func bpfFramedProgramHandler(syzType *prog.StructType, traceType irType, ctx *Context) irType {
	switch a := traceType.(type) {
	case *arrayType:
		straceStructArgs := make([]irType, len(syzType.Fields))
		arrType := a
		straceStructArgs[1] = arrType
		straceArg0 := genDefaultTraceType(syzType.Fields[0])
		straceStructArgs[0] = straceArg0
		straceStructArgs = append(straceStructArgs, genDefaultTraceType(syzType.Fields[1]))
		return newStructType(straceStructArgs)
	}
	return traceType
}
