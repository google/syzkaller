package proggen

import (
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/tools/syz-trace2syz/parser"
)

var discriminatorArgs = map[string][]int{
	"bpf":         {0},
	"fcntl":       {1},
	"ioprio_get":  {0},
	"socket":      {0, 1, 2},
	"socketpair":  {0, 1, 2},
	"ioctl":       {0, 1},
	"getsockopt":  {1, 2},
	"setsockopt":  {1, 2},
	"accept":      {0},
	"accept4":     {0},
	"bind":        {0},
	"connect":     {0},
	"recvfrom":    {0},
	"sendto":      {0},
	"sendmsg":     {0},
	"getsockname": {0},
}

type callSelector struct {
	callCache map[string][]*prog.Syscall
}

func newCallSelector() *callSelector {
	return &callSelector{callCache: make(map[string][]*prog.Syscall)}
}

// Select returns the best matching descrimination for this syscall.
func (cs *callSelector) Select(ctx *Context, call *parser.Syscall) *prog.Syscall {
	match := ctx.Target.SyscallMap[call.CallName]
	discriminators := discriminatorArgs[call.CallName]
	if len(discriminators) == 0 {
		return match
	}
	score := 0
	for _, meta := range cs.callSet(ctx, call.CallName) {
		if score1 := matchCall(ctx, meta, call, discriminators); score1 > score {
			match, score = meta, score1
		}
	}
	return match
}

// callSet returns all syscalls with the given name.
func (cs *callSelector) callSet(ctx *Context, callName string) []*prog.Syscall {
	calls, ok := cs.callCache[callName]
	if ok {
		return calls
	}
	for _, call := range ctx.Target.Syscalls {
		if call.CallName == callName {
			calls = append(calls, call)
		}
	}
	cs.callCache[callName] = calls
	return calls
}

// matchCall returns match score between meta and call.
// Higher score means better match, -1 if they are not matching at all.
func matchCall(ctx *Context, meta *prog.Syscall, call *parser.Syscall, discriminators []int) int {
	score := 0
	for _, i := range discriminators {
		if i >= len(meta.Args) || i >= len(call.Args) {
			return -1
		}
		typ := meta.Args[i]
		arg := call.Args[i]
		switch t := typ.(type) {
		case *prog.ConstType:
			// Consts must match precisely.
			constant, ok := arg.(parser.Constant)
			if !ok || constant.Val() != t.Val {
				return -1
			}
			score += 10
		case *prog.FlagsType:
			// Flags may or may not match, but matched flags increase score.
			constant, ok := arg.(parser.Constant)
			if !ok {
				return -1
			}
			val := constant.Val()
			for _, v := range t.Vals {
				if v == val {
					score++
					break
				}
			}
		case *prog.ResourceType:
			// Resources must match one of subtypes,
			// the more precise match, the higher the score.
			retArg := ctx.ReturnCache.get(t, arg)
			if retArg == nil {
				return -1
			}
			matched := false
			for i, kind := range retArg.Type().(*prog.ResourceType).Desc.Kind {
				if kind == t.Desc.Name {
					score += i + 1
					matched = true
					break
				}
			}
			if !matched {
				return -1
			}
		}
	}
	return score
}
