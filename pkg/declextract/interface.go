// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package declextract

import (
	"slices"
	"strings"

	"github.com/google/syzkaller/pkg/cover"
)

type Interface struct {
	Type               string
	Name               string
	IdentifyingConst   string
	Files              []string
	Func               string
	Access             string
	Subsystems         []string
	ManualDescriptions TristateVal
	AutoDescriptions   TristateVal
	ReachableLOC       int
	CoveredBlocks      int
	TotalBlocks        int

	scopeArg int
	scopeVal string
}

type TristateVal int

const (
	TristateUnknown TristateVal = iota
	TristateYes
	TristateNo
)

const (
	IfaceSyscall   = "SYSCALL"
	IfaceNetlinkOp = "NETLINK"
	IfaceFileop    = "FILEOP"
	IfaceIoctl     = "IOCTL"
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
	ctx.interfaces = sortAndDedupSlice(ctx.interfaces)
	count := make(map[string]int)
	for _, iface := range ctx.interfaces {
		count[iface.Type+iface.Name]++
	}
	// Lots of file ops have the same name, add file name to them.
	for _, iface := range ctx.interfaces {
		if count[iface.Type+iface.Name] > 1 {
			iface.Name = iface.Name + "_" + fileNameSuffix(iface.Files[0])
		}
	}
	for _, iface := range ctx.interfaces {
		ctx.calculateLOC(iface)
		slices.Sort(iface.Files)
		iface.Files = slices.Compact(iface.Files)
		if iface.Access == "" {
			iface.Access = AccessUnknown
		}
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
	coverBlocks := make(map[string][]*cover.Block)
	for _, file := range ctx.coverage {
		for _, fn := range file.Functions {
			coverBlocks[file.FilePath+fn.FuncName] = fn.Blocks
		}
	}
	for _, fn := range ctx.Functions {
		for _, block := range coverBlocks[fn.File+fn.Name] {
			var match *FunctionScope
			for _, scope := range fn.Scopes {
				if scope.Arg == -1 {
					match = scope
				}
				if block.FromLine >= scope.StartLine && block.FromLine <= scope.EndLine {
					match = scope
					break
				}
			}
			match.totalBlocks++
			if block.HitCount != 0 {
				match.coveredBlocks++
			}
		}
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

func (ctx *context) calculateLOC(iface *Interface) {
	fn := ctx.findFunc(iface.Func, iface.Files[0])
	if fn == nil {
		ctx.warn("can't find function %v called in %v", iface.Func, iface.Files[0])
		return
	}
	scopeFnArgs := ctx.inferArgFlow(fnArg{fn, iface.scopeArg})
	visited := make(map[*Function]bool)
	iface.ReachableLOC = ctx.collectLOC(iface, fn, scopeFnArgs, iface.scopeVal, visited)
}

func (ctx *context) collectLOC(iface *Interface, fn *Function, scopeFnArgs map[fnArg]bool,
	scopeVal string, visited map[*Function]bool) int {
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
		iface.TotalBlocks += scope.totalBlocks
		iface.CoveredBlocks += scope.coveredBlocks
		for _, callee := range scope.calls {
			if visited[callee] || callee.callers >= commonFuncThreshold {
				continue
			}
			loc += ctx.collectLOC(iface, callee, scopeFnArgs, scopeVal, visited)
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

func (ctx *context) funcDefinitionFile(name, calledFrom string) string {
	fn := ctx.findFunc(name, calledFrom)
	if fn == nil {
		return ""
	}
	return fn.File
}

func fileNameSuffix(file string) string {
	// Remove file extension.
	ext := strings.LastIndexByte(file, '.')
	if ext != -1 {
		file = file[:ext]
	}
	raw := []byte(file)
	for i, v := range raw {
		if v >= 'a' && v <= 'z' || v >= 'A' && v <= 'Z' || v >= '0' && v <= '9' {
			continue
		}
		raw[i] = '_'
	}
	return string(raw)
}

func Tristate(v bool) TristateVal {
	if v {
		return TristateYes
	}
	return TristateNo
}

func (tv TristateVal) String() string {
	switch tv {
	case TristateYes:
		return "true"
	case TristateNo:
		return "false"
	default:
		return "unknown"
	}
}
