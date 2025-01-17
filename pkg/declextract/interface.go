// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package declextract

import (
	"slices"
	"strings"
)

type Interface struct {
	Type               string
	Name               string
	IdentifyingConst   string
	Files              []string
	Func               string
	Access             string
	Subsystems         []string
	ManualDescriptions bool
	AutoDescriptions   bool
	ReachableLOC       int
}

const (
	IfaceSyscall   = "SYSCALL"
	IfaceNetlinkOp = "NETLINK"
	IfaceIouring   = "IOURING"

	AccessUnknown = "unknown"
	AccessUser    = "user"
	AccessNsAdmin = "ns_admin"
	AccessAdmin   = "admin"
)

func (ctx *context) noteInterface(iface *Interface) {
	ctx.interfaces = append(ctx.interfaces, iface)
}

func (ctx *context) finishInterfaces() {
	for _, iface := range ctx.interfaces {
		iface.ReachableLOC = ctx.reachableLOC(iface.Func, iface.Files[0])
		slices.Sort(iface.Files)
		iface.Files = slices.Compact(iface.Files)
		if iface.Access == "" {
			iface.Access = AccessUnknown
		}
	}
	ctx.interfaces = sortAndDedupSlice(ctx.interfaces)
}

func (ctx *context) processFunctions() {
	for _, fn := range ctx.Functions {
		ctx.funcs[fn.File+fn.Name] = fn
		// Strictly speaking there may be several different static functions in different headers,
		// but we ignore such possibility for now.
		if !fn.IsStatic || strings.HasSuffix(fn.File, ".h") {
			ctx.funcs[fn.Name] = fn
		}
	}
	nocallers := 0
	for _, fn := range ctx.Functions {
		for _, scope := range fn.Scopes {
			for _, callee := range scope.Calls {
				called := ctx.findFunc(callee, fn.File)
				if called == nil || called == fn {
					continue
				}
				fn.calls = append(fn.calls, called)
				called.callers++
			}
		}
		if len(fn.calls) == 0 {
			nocallers++
		}
	}
}

func (ctx *context) reachableLOC(name, file string) int {
	fn := ctx.findFunc(name, file)
	if fn == nil {
		ctx.warn("can't find function %v called in %v", name, file)
		return 0
	}
	reachable := make(map[*Function]bool)
	ctx.collectRachable(fn, reachable)
	loc := 0
	for fn := range reachable {
		for _, scope := range fn.Scopes {
			loc += scope.LOC
		}
	}
	return loc
}

func (ctx *context) collectRachable(fn *Function, reachable map[*Function]bool) {
	// Ignore very common functions when computing reachability for complexity analysis.
	// Counting kmalloc/printk against each caller is not useful (they have ~10K calls).
	// There are also subsystem common functions (e.g. functions called in some parts of fs/net).
	// The current threshold is somewhat arbitrary and is based on the number of callers in syzbot kernel:
	// 6 callers - 2272 functions
	// 5 callers - 3468 functions
	// 4 callers - 6295 functions
	// 3 callers - 16527 functions
	const commonFuncThreshold = 5

	reachable[fn] = true
	for _, callee := range fn.calls {
		if reachable[callee] || callee.callers >= commonFuncThreshold {
			continue
		}
		ctx.collectRachable(callee, reachable)
	}
}

func (ctx *context) findFunc(name, file string) *Function {
	if fn := ctx.funcs[file+name]; fn != nil {
		return fn
	}
	return ctx.funcs[name]
}
