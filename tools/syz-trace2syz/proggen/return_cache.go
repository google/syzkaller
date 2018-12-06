package proggen

import (
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/tools/syz-trace2syz/parser"
)

type resourceDescription struct {
	Type string
	Val  string
}

type returnCache map[resourceDescription]prog.Arg

func newRCache() returnCache {
	return make(map[resourceDescription]prog.Arg)
}

func (r *returnCache) buildKey(syzType prog.Type) string {
	switch a := syzType.(type) {
	case *prog.ResourceType:
		return a.Desc.Kind[0]
	default:
		log.Fatalf("caching non resource type")
	}
	return ""
}

func (r *returnCache) cache(syzType prog.Type, traceType parser.IrType, arg prog.Arg) {
	log.Logf(2, "caching resource: %s, val: %s", r.buildKey(syzType), traceType.String())
	resDesc := resourceDescription{
		Type: r.buildKey(syzType),
		Val:  traceType.String(),
	}
	(*r)[resDesc] = arg
}

func (r *returnCache) get(syzType prog.Type, traceType parser.IrType) prog.Arg {
	log.Logf(2, "fetching resource: %s, val: %s", r.buildKey(syzType), traceType.String())
	resDesc := resourceDescription{
		Type: r.buildKey(syzType),
		Val:  traceType.String(),
	}
	if arg, ok := (*r)[resDesc]; ok {
		if arg != nil {
			log.Logf(2, "cache hit for resource type: %s, val: %s", r.buildKey(syzType), traceType.String())
			return arg
		}
	}
	return nil
}
