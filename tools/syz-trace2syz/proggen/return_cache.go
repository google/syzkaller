package proggen

import (
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/tools/syz-trace2syz/parser"
)

type returnCache map[string]prog.Arg

func newRCache() returnCache {
	return make(map[string]prog.Arg)
}

func returnCacheKey(syzType prog.Type, traceType parser.IrType) string {
	a, ok := syzType.(*prog.ResourceType)
	if !ok {
		log.Fatalf("caching non resource type")
	}
	return a.Desc.Kind[0] + "-" + traceType.String()
}

func (r returnCache) cache(syzType prog.Type, traceType parser.IrType, arg prog.Arg) {
	log.Logf(2, "caching resource: %v", returnCacheKey(syzType, traceType))
	r[returnCacheKey(syzType, traceType)] = arg
}

func (r returnCache) get(syzType prog.Type, traceType parser.IrType) prog.Arg {
	log.Logf(2, "fetching resource: %s, val: %s", returnCacheKey(syzType, traceType))
	return r[returnCacheKey(syzType, traceType)]
}
