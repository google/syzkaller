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

	scopeArg int
	scopeVal string
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
		iface.ReachableLOC = ctx.reachableLOC(iface.Func, iface.Files[0], iface.scopeArg, iface.scopeVal)
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
	for _, fn := range ctx.Functions {
		for _, scope := range fn.Scopes {
			for _, callee := range scope.Calls {
				called := ctx.findFunc(callee, fn.File)
				if called == nil || called == fn {
					continue
				}
				scope.calls = append(scope.calls, called)
				called.callers++
			}
		}
	}
}

func (ctx *context) reachableLOC(name, file string, scopeArg int, scopeVal string) int {
	fn := ctx.findFunc(name, file)
	if fn == nil {
		ctx.warn("can't find function %v called in %v", name, file)
		return 0
	}
	scopeFnArgs := ctx.inferArgFlow(fnArg{fn, scopeArg})
	visited := make(map[*Function]bool)
	return ctx.collectLOC(fn, scopeFnArgs, scopeVal, visited)
}

func (ctx *context) collectLOC(fn *Function, scopeFnArgs map[fnArg]bool, scopeVal string,
	visited map[*Function]bool) int {
	// Ignore very common functions when computing reachability for complexity analysis.
	// Counting kmalloc/printk against each caller is not useful (they have ~10K calls).
	// There are also subsystem common functions (e.g. functions called in some parts of fs/net).
	// The current threshold is somewhat arbitrary and is based on the number of callers in syzbot kernel:
	// 6 callers - 2272 functions
	// 5 callers - 3468 functions
	// 4 callers - 6295 functions
	// 3 callers - 16527 functions
	const commonFuncThreshold = 5

	visited[fn] = true
	loc := max(0, fn.EndLine-fn.StartLine-1)
	for _, scope := range fn.Scopes {
		if !relevantScope(scopeFnArgs, scopeVal, scope) {
			loc -= max(0, scope.EndLine-scope.StartLine)
			continue
		}
		for _, callee := range scope.calls {
			if visited[callee] || callee.callers >= commonFuncThreshold {
				continue
			}
			loc += ctx.collectLOC(callee, scopeFnArgs, scopeVal, visited)
		}
	}
	return loc
}

func (ctx *context) findFunc(name, file string) *Function {
	if fn := ctx.funcs[file+name]; fn != nil {
		return fn
	}
	return ctx.funcs[name]
}
