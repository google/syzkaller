// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// syz-callgraph parses the Linux kernel source call graph
// and prints how many times each function is called and its callers.
// Run as:
//
//	syz-callgraph -kernel_obj <path to kernel build directory built with clang>
//
// The output format is:
//
//	number-of-caller-functions/number-of-caller-files: function-name: callers
//
// For example:
//
//	005248/001316 _raw_spin_lock: ax25_get_socket tcf_block_insert gfs2_put_super lock_stripe_add nfsd4_lock
//	005436/001339 _raw_spin_unlock: self_check_volume is_ses_using_iface gfs2_quota_cleanup blk_mq_mark_tag_wait
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/tool"
	"gonum.org/v1/gonum/graph/formats/dot"
	"gonum.org/v1/gonum/graph/formats/dot/ast"
)

type CallGraph struct {
	Funcs map[string]*Func
	Edges int
}

type Func struct {
	Name                  string
	Callees               map[string]*Func
	Callers               map[string]*Func
	CallerFiles           int
	TransitiveCallers     int
	TransitiveCallerFiles int
}

func NewCallGraph() *CallGraph {
	return &CallGraph{
		Funcs: make(map[string]*Func),
	}
}

func (cg *CallGraph) Insert(f, t string) {
	if f == t {
		return
	}
	from := cg.findFunc(f)
	if from.Callees[t] != nil {
		return
	}
	to := cg.findFunc(t)
	from.Callees[t] = to
	to.Callers[f] = from
	cg.Edges++
}

func (cg *CallGraph) Merge(other *CallGraph) {
	for name, fn := range other.Funcs {
		cg.findFunc(name).CallerFiles++
		for from := range fn.Callers {
			cg.Insert(from, name)
		}
	}
}

type cycle struct {
	funcs map[*Func]bool
}

func (c *cycle) String() string {
	var names []string
	for fn := range c.funcs {
		names = append(names, fn.Name)
	}
	sort.Strings(names)
	return strings.Join(names, " -> ")
}

func (cg *CallGraph) CalcClosure() {
	cycles := make(map[*cycle]bool)
	funcToCycle := make(map[*Func]*cycle)
	funcCycles := make(map[*Func]int)
	visited := make(map[*Func]bool)
	var dfs func(fn *Func, path []*Func)
	dfs = func(fn *Func, path []*Func) {
		if visited[fn] {
			for i, caller := range path {
				if caller != fn {
					continue
				}
				c := &cycle{
					funcs: make(map[*Func]bool),
				}
				cycles[c] = true

				var names []string
				for _, fn := range path[i:] {
					names = append(names, fn.Name)
				}
				sort.Strings(names)
				fmt.Printf("detected cycle: %v\n", strings.Join(names, " -> "))

				for _, fn := range path[i:] {
					funcCycles[fn]++
					c.funcs[fn] = true
					if other := funcToCycle[fn]; other != nil && other != c {
						fmt.Printf("merging existing due to %v: %v\n", fn.Name, other)

						for otherFn := range other.funcs {
							c.funcs[otherFn] = true
							funcToCycle[otherFn] = c
						}
						delete(cycles, other)
					}
					funcToCycle[fn] = c
				}
				break
			}
			return
		}
		visited[fn] = true
		path = append(path, fn)
		for _, callee := range fn.Callees {
			dfs(callee, path)
		}
	}
	for _, fn := range cg.Funcs {
		fn.TransitiveCallers = 0
		fn.TransitiveCallerFiles = 0
		dfs(fn, nil)
	}
	fmt.Printf("merged cycles %v:\n", len(cycles))
	for c := range cycles {
		fmt.Printf("cycle: %v\n", c)
	}
	for fn, count := range funcCycles {
		fmt.Printf("func cycles %v: %v\n", count, fn.Name)
	}

}

func (cg *CallGraph) findFunc(name string) *Func {
	f := cg.Funcs[name]
	if f != nil {
		return f
	}
	f = &Func{
		Name:    name,
		Callees: make(map[string]*Func),
		Callers: make(map[string]*Func),
	}
	cg.Funcs[name] = f
	return f
}

type Task struct {
	dir  string
	file string
	err  error
	cg   *CallGraph
}

func main() {
	flagKernelObj := flag.String("kernel_obj", "", "path to kernel build directory")
	defer tool.Init()()
	flag.Parse()
	// Find all .o.cmd files, they contain compilation commands.
	files := []string{}
	fileRe := regexp.MustCompile(`/\..*\.o\.cmd$`)
	err := filepath.Walk(*flagKernelObj, func(path string, f os.FileInfo, err error) error {
		if fileRe.MatchString(path) {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		tool.Fail(err)
	}
	inputs := make(chan *Task, len(files))
	for _, file := range files {
		inputs <- &Task{
			dir:  *flagKernelObj,
			file: file,
		}
	}
	close(inputs)
	outputs := make(chan *Task, len(files))
	for p := 0; p < runtime.NumCPU(); p++ {
		go func() {
			for t := range inputs {
				t.err = processTask(t)
				outputs <- t
			}
		}()
	}
	errors := 0
	cg := NewCallGraph()
	for i := range files {
		t := <-outputs
		if t.err != nil {
			fmt.Fprintf(os.Stderr, "%v: %v\n", filepath.Base(t.file), t.err)
			errors++
			continue
		}
		fmt.Fprintf(os.Stderr, "\r\033[K[%v/%v] %v: %v funcs, %v edges",
			i, len(files), filepath.Base(t.file), len(t.cg.Funcs), t.cg.Edges)
		cg.Merge(t.cg)
	}

	var results []string
	for name, fn := range cg.Funcs {
		res := fmt.Sprintf("%06v/%06v %v:", len(fn.Callers), fn.CallerFiles, name)
		for from := range fn.Callers {
			res += " " + from
			if len(res) > 100 {
				break
			}
		}
		results = append(results, res)
	}
	sort.Strings(results)
	for _, res := range results {
		fmt.Printf("%s\n", res)
	}

	for _, fn := range cg.Funcs {
		if fn.CallerFiles < 10 {
			continue
		}
		var names []string
		visited := make(map[*Func]bool)
		var dfs func(fn *Func)
		dfs = func(fn *Func) {
			visited[fn] = true
			for _, callee := range fn.Callees {
				if visited[callee] {
					continue
				}
				names = append(names, callee.Name)
				dfs(callee)
			}
		}
		dfs(fn)
		fmt.Printf("common func: %v transitive %v: %v\n", fn.Name, len(names), names)
	}

	cg.CalcClosure()
	fmt.Printf("total: %v funcs, %v edges\n", len(cg.Funcs), cg.Edges)
	if errors != 0 {
		tool.Failf("failed to process %v files", errors)
	}
}

func processTask(t *Task) error {
	t.cg = NewCallGraph()
	dotFile, err := createDot(t)
	if err != nil || dotFile == nil {
		return err
	}
	funcs := make(map[string]string)
	for _, graph := range dotFile.Graphs {
		// First collect all ID -> function name mappings.
		for _, stmt := range graph.Stmts {
			node, ok := stmt.(*ast.NodeStmt)
			if !ok {
				continue
			}
			name := ""
			for _, attr := range node.Attrs {
				if attr.Key == "label" {
					name = attr.Val[2 : len(attr.Val)-2]
				}
			}
			if strings.HasPrefix(name, "llvm.") {
				// Convert back these common intrinsics.
				switch {
				case strings.HasPrefix(name, "llvm.memset"):
					name = "memset"
				case strings.HasPrefix(name, "llvm.memcpy"):
					name = "memcpy"
				case strings.HasPrefix(name, "llvm.memmove"):
					name = "memmove"
				default:
					// The rest of intrinsics are not interesting.
					continue
				}
			}
			funcs[node.Node.ID] = name
		}
		// Now collect caller/callee edges.
		for _, stmt := range graph.Stmts {
			edge, ok := stmt.(*ast.EdgeStmt)
			if !ok {
				continue
			}
			from := funcs[edge.From.(*ast.Node).ID]
			to := funcs[edge.To.Vertex.(*ast.Node).ID]
			t.cg.Insert(from, to)
		}
	}
	return nil
}

var cmdRe = regexp.MustCompile("savedcmd_.* := (.*?)\n+source_.* := .*?\\.c\\n")

func createDot(t *Task) (*ast.File, error) {
	data, err := os.ReadFile(t.file)
	if err != nil {
		return nil, err
	}
	match := cmdRe.FindSubmatch(data)
	if match == nil {
		return nil, nil
	}
	cmd := string(match[1])

	clangPath, clangBin := filepath.Split(strings.Fields(cmd)[0])
	if !strings.HasPrefix(clangBin, "clang") {
		return nil, nil
	}
	optBin := filepath.Join(clangPath, "opt"+strings.TrimPrefix(clangBin, "clang"))

	graphFile, err := osutil.TempFile("syz-callgraph")
	if err != nil {
		return nil, err
	}
	defer os.Remove(graphFile)

	// It's tricky to unescape strings in arguments, so we use bash to do it.
	// Also handy to pipe via opt in one invocation.
	addArgs := " -w -O0 -g0 -S -emit-llvm -o - | " +
		optBin + " -o /dev/null --passes dot-callgraph --callgraph-dot-filename-prefix " + graphFile
	if _, err := osutil.RunCmd(10*time.Minute, t.dir, "bash", "-c", cmd+addArgs); err != nil {
		return nil, err
	}
	return dot.ParseFile(graphFile + ".callgraph.dot")
}
