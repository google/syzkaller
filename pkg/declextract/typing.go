// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package declextract

import (
	"bytes"
	"fmt"
	"slices"
	"strings"
)

// Argument/field type inference based on data flow analysis.
//
// First, the clang tool produces data flow summary for each function.
// The summary describes how data flows between function arguments, return values, local variables, and struct fields.
// Then, the logic in this file tracks global data flow in the kernel to infer types for syscall arguments,
// return values, and struct fields.
// If data transitively flows from an argument to a known function that accepts a resource of a particular type
// (e.g. __fget_light for file descriptors), then we infer that the original argument is an fd.
// Similarly, if data flows from a known function that creates a resource (e.g. alloc_fd for file descriptors)
// to a syscall return value, then we infer that the syscall returns an fd.
// For struct fields we track data flow in both direction (to/from) to infer their types.
//
// If the inference produces multiple resources, currently we pick the one with the shortest flow path
// (and then additionally pick lexicographically first among them for determinism). Potentially we could
// use a more elaborate strategy that would somehow rank candidates and/or produce multiple candidates
// (that we will then use as a union).
//
// Other potential improvements:
// - Add more functions that consume/produce resources.
// - Refine enum types. If we see an argument is used in bitops with an enum, it has that enum type.
// - Infer pointer types when they flow to copy_from_user (sometimes they are declared as uint64).
// - Infer that pointers are file names (they should flow to some known function for path resolution).
// - Use SSA analysis to track flow via local variables better. Potentiall we can just rename on every next use
//   and ignore backwards edges (it's unlikely that backwards edges are required for type inference).
// - Infer ioctl commands in transitively called functions using data flow.
// - Infer file_operations associated with an fd by tracking flow to alloc_file_pseudo and friends.
// - Add context-sensitivity at least on switched arguments (ioctl commands).
// - Infer other switched arguments besides ioctl commands.
// - Infer netlink arg types by tracking flow from genl_info::attrs[ATTR_FOO].
// - Infer simple constraints on arguments, e.g. "if (arg != 0) return -EINVAL".
// - Use kernel typedefs for typing (e.g. pid_t). We can use them for uapi structs, but also for kernel
//   structs and function arguments during dataflow tracking (e.g. if int flows to a pid_t argument, it's a pid).
// - Track side flows. E.g. dup2 argument newfd flows to the return value, and newfd can be inferred to be an fd,
//   but currently we don't infer that the return value is an fd. Potentially we could infer that.
// - Detect cases where returned value is actually an error rather than a resource.
//   For example, these cases lead to false inference of fd type for returned value:
//   https://elixir.bootlin.com/linux/v6.13-rc2/source/net/core/sock.c#L1870
//   https://elixir.bootlin.com/linux/v6.13-rc2/source/net/socket.c#L1742

var (
	// Refines types based on data flows...
	flowResources = [2]map[string]string{
		// ...to function arguments.
		{
			"__fget_light:arg0":       "fd",
			"__fget_files_rcu:arg1":   "fd",
			"make_kuid:arg1":          "uid",
			"make_kgid:arg1":          "gid",
			"find_pid_ns:arg0":        "pid",
			"pidfd_get_pid:arg0":      "fd_pidfd",
			"__dev_get_by_index:arg1": "ifindex",
		},
		// ...from function return value.
		{
			"alloc_fd:ret":  "fd",
			"pid_nr_ns:ret": "pid",
			"from_kuid:ret": "uid",
			"from_kgid:ret": "gid",
		},
	}
	// These functions/structs/files provide very high false connectivity between unrelated nodes.
	flowIgnoreFuncs = map[string]bool{
		"ptr_to_compat": true,
		"compat_ptr":    true,
	}
	flowIgnoreStructs = map[string]bool{
		"pt_regs": true,
		"io_cqe":  true,
		"inode":   true,
	}
	flowIgnoreFiles = map[string]bool{
		"include/linux/err.h":     true, // PTR_ERR/ERR_PTR/ERR_CAST
		"include/linux/byteorder": true, // ntohl/etc
		"include/linux/uaccess.h": true, // copy_to/from_user
		"fs/befs/endian.h":        true, // cpu_to_fs32/etc
		"fs/ufs/swab.h":           true,
	}
)

// Limit on the flow graph traversal depth to avoid false positives due to false weird connections.
const maxTraversalDepth = 18

type typingNode struct {
	id    string
	fn    *Function
	arg   int
	flows [2]map[*typingNode]bool
}

const (
	flowTo = iota
	flowFrom
)

func (ctx *context) processTypingFacts() {
	for _, fn := range ctx.Functions {
		for _, scope := range fn.Scopes {
			for _, fact := range scope.Facts {
				src := ctx.canonicalNode(fn, fact.Src)
				dst := ctx.canonicalNode(fn, fact.Dst)
				if src == nil || dst == nil {
					continue
				}
				src.flows[flowTo][dst] = true
				dst.flows[flowFrom][src] = true
			}
		}
	}
}

func (ctx *context) canonicalNode(fn *Function, ent *TypingEntity) *typingNode {
	scope, id := ent.ID(fn)
	fullID := id
	facts := ctx.facts
	if scope != "" {
		if scope != fn.Name {
			fn = ctx.findFunc(scope, fn.File)
			if fn == nil {
				return nil
			}
		}
		if flowIgnoreFuncs[fn.Name] || flowIgnoreFiles[fn.File] {
			return nil
		}
		if fn.facts == nil {
			fn.facts = make(map[string]*typingNode)
		}
		facts = fn.facts
		fullID = fmt.Sprintf("%v:%v", scope, id)
	} else if ent.Field != nil && flowIgnoreStructs[ent.Field.Struct] {
		return nil
	}
	n := facts[id]
	if n != nil {
		return n
	}
	arg := -1
	if ent.Argument != nil {
		arg = ent.Argument.Arg
	}
	n = &typingNode{
		id:  fullID,
		fn:  fn,
		arg: arg,
	}
	for i := range n.flows {
		n.flows[i] = make(map[*typingNode]bool)
	}
	facts[id] = n
	return n
}

func (ent *TypingEntity) ID(fn *Function) (string, string) {
	switch {
	case ent.Return != nil:
		return ent.Return.Func, "ret"
	case ent.Argument != nil:
		return ent.Argument.Func, fmt.Sprintf("arg%v", ent.Argument.Arg)
	case ent.Local != nil:
		return fn.Name, fmt.Sprintf("loc.%v", ent.Local.Name)
	case ent.Field != nil:
		return "", fmt.Sprintf("%v.%v", ent.Field.Struct, ent.Field.Field)
	case ent.GlobalAddr != nil:
		return "", ent.GlobalAddr.Name
	default:
		panic("unhandled type")
	}
}

func (ctx *context) inferReturnType(name, file string) string {
	return ctx.inferFuncNode(name, file, "ret")
}

func (ctx *context) inferArgType(name, file string, arg int) string {
	return ctx.inferFuncNode(name, file, fmt.Sprintf("arg%v", arg))
}

func (ctx *context) inferFuncNode(name, file, node string) string {
	fn := ctx.findFunc(name, file)
	if fn == nil {
		return ""
	}
	return ctx.inferNodeType(fn.facts[node], fmt.Sprintf("%v %v", name, node))
}

func (ctx *context) inferFieldType(structName, field string) string {
	name := fmt.Sprintf("%v.%v", structName, field)
	return ctx.inferNodeType(ctx.facts[name], name)
}

func (ctx *context) inferNodeType(n *typingNode, what string) string {
	if n == nil {
		return ""
	}
	ic := &inferContext{
		visited:  make(map[*typingNode]bool),
		flowType: flowFrom,
		maxDepth: maxTraversalDepth,
	}
	ic.walk(n)
	ic.flowType = flowTo
	ic.visited = make(map[*typingNode]bool)
	ic.walk(n)
	if ic.result != "" {
		ctx.trace("inferred %v\n  %v%v", what, ic.result, flowString(ic.resultPath, ic.resultFlow))
	}
	return ic.result
}

type inferContext struct {
	path       []*typingNode
	visited    map[*typingNode]bool
	result     string
	resultPath []*typingNode
	resultFlow int
	flowType   int
	maxDepth   int
}

func (ic *inferContext) walk(n *typingNode) {
	if ic.visited[n] {
		return
	}
	ic.visited[n] = true
	ic.path = append(ic.path, n)
	if result, ok := flowResources[ic.flowType][n.id]; ok {
		// Use lexicographical order just to make the result stable.
		if ic.result == "" || len(ic.path) < ic.maxDepth ||
			len(ic.path) == ic.maxDepth && strings.Compare(result, ic.result) < 0 {
			ic.result = result
			ic.resultPath = slices.Clone(ic.path)
			ic.resultFlow = ic.flowType
			ic.maxDepth = len(ic.path)
		}
	}
	if len(ic.path) < ic.maxDepth {
		for e := range n.flows[ic.flowType] {
			ic.walk(e)
		}
	}
	ic.path = ic.path[:len(ic.path)-1]
}

func refineFieldType(f *Field, typ string, preserveSize bool) {
	// If our manual heuristics have figured out a more precise fd subtype,
	// don't replace it with generic fd.
	if typ == "" || typ == f.syzType ||
		typ == "fd" && (strings.HasPrefix(f.syzType, "fd_") || strings.HasPrefix(f.syzType, "sock")) {
		return
	}
	// For struct fields we need to keep the original size.
	// Sometimes fd is passed as uint64.
	if preserveSize {
		typ = fmt.Sprintf("auto_union[%v, %v]", typ, f.syzType)
	}
	f.syzType = typ
}

func flowString(path []*typingNode, flowType int) string {
	w := new(bytes.Buffer)
	dir := [2]string{"->", "<-"}[flowType]
	for _, e := range path {
		fmt.Fprintf(w, " %v %v", dir, e.id)
	}
	return w.String()
}

func (ctx *context) inferCommandVariants(name, file string, arg int) []string {
	ctx.trace("inferring %v:arg%v variants", name, arg)
	fn := ctx.findFunc(name, file)
	if fn == nil {
		return nil
	}
	var variants []string
	n := fn.facts[fmt.Sprintf("arg%v", arg)]
	if n == nil {
		ctx.collectCommandVariants(fn, arg, &variants)
	} else {
		visited := make(map[*typingNode]bool)
		ctx.walkCommandVariants(n, &variants, visited, 0)
	}
	return sortAndDedupSlice(variants)
}

func (ctx *context) collectCommandVariants(fn *Function, arg int, variants *[]string) {
	var values []string
	for _, scope := range fn.Scopes {
		if scope.Arg == arg {
			values = append(values, scope.Values...)
		}
	}
	if len(values) != 0 {
		ctx.trace("  function %v:arg%v implements: %v", fn.Name, arg, values)
		*variants = append(*variants, values...)
	}
}

func (ctx *context) walkCommandVariants(n *typingNode, variants *[]string, visited map[*typingNode]bool, depth int) {
	if visited[n] || depth >= 10 {
		return
	}
	visited[n] = true
	if n.arg >= 0 {
		ctx.collectCommandVariants(n.fn, n.arg, variants)
	}
	for e := range n.flows[flowTo] {
		ctx.walkCommandVariants(e, variants, visited, depth+1)
	}
}
