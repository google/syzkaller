// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"bytes"
	"fmt"
	"reflect"

	"github.com/bits-and-blooms/bloom/v3"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/stat"
)

var (
	statMinRemoveCall = stat.New("minimize: call",
		"Total number of remove call attempts during minimization", stat.StackedGraph("minimize"))
	statMinRemoveProps = stat.New("minimize: props",
		"Total number of remove properties attempts during minimization", stat.StackedGraph("minimize"))
	statMinPtr = stat.New("minimize: pointer",
		"Total number of pointer minimization attempts", stat.StackedGraph("minimize"))
	statMinArray = stat.New("minimize: array",
		"Total number of array minimization attempts", stat.StackedGraph("minimize"))
	statMinInt = stat.New("minimize: integer",
		"Total number of integer minimization attempts", stat.StackedGraph("minimize"))
	statMinResource = stat.New("minimize: resource",
		"Total number of resource minimization attempts", stat.StackedGraph("minimize"))
	statMinBuffer = stat.New("minimize: buffer",
		"Total number of buffer minimization attempts", stat.StackedGraph("minimize"))
	statMinFilename = stat.New("minimize: filename",
		"Total number of filename minimization attempts", stat.StackedGraph("minimize"))
)

type Cache struct {
	Uses []map[any]bool
	Bfs  []*bloom.BloomFilter
}

type MinimizeMode int

const (
	// Minimize for inclusion into corpus.
	// This generally tries to reduce number of arguments for future mutation.
	MinimizeCorpus MinimizeMode = iota
	// Minimize crash reproducer.
	// This mode assumes each test is expensive (need to reboot), so tries fewer things.
	MinimizeCrash
	// Minimize crash reproducer in snapshot mode.
	// This mode does not assume that tests are expensive, and tries to minimize for reproducer readability.
	MinimizeCrashSnapshot
	// Only try to remove calls.
	MinimizeCallsOnly
)

// Minimize minimizes program p into an equivalent program using the equivalence
// predicate pred. It iteratively generates simpler programs and asks pred
// whether it is equal to the original program or not. If it is equivalent then
// the simplification attempt is committed and the process continues.
func Minimize(p0 *Prog, callIndex0 int, mode MinimizeMode, pred0 func(*Prog, int) bool) (*Prog, int) {
	// Generally we try to avoid generating duplicates, but in some cases they are hard to avoid.
	// For example, if we have an array with several equal elements, removing them leads to the same program.
	dedup := make(map[string]bool)
	pred := func(p *Prog, callIndex int, what *stat.Val, path string) bool {
		// Note: path is unused, but is useful for manual debugging.
		what.Add(1)
		p.sanitizeFix()
		p.debugValidate()
		id := hash.String(p.Serialize())
		if _, ok := dedup[id]; !ok {
			dedup[id] = pred0(p, callIndex)
		}
		return dedup[id]
	}
	name0 := ""
	if callIndex0 != -1 {
		if callIndex0 < 0 || callIndex0 >= len(p0.Calls) {
			panic("bad call index")
		}
		name0 = p0.Calls[callIndex0].Meta.Name
	}

	// Try to remove all calls except the last one one-by-one.
	p0, callIndex0 = removeCalls(p0, callIndex0, pred)

	if mode != MinimizeCallsOnly {
		// Try to reset all call props to their default values.
		p0 = resetCallProps(p0, callIndex0, pred)

		// Try to minimize individual calls.
		for i := 0; i < len(p0.Calls); i++ {
			if p0.Calls[i].Meta.Attrs.NoMinimize {
				continue
			}
			ctx := &minimizeArgsCtx{
				target:     p0.Target,
				p0:         &p0,
				callIndex0: callIndex0,
				mode:       mode,
				pred:       pred,
				triedPaths: make(map[string]bool),
			}
		again:
			ctx.p = p0.Clone()
			ctx.call = ctx.p.Calls[i]
			for j, field := range ctx.call.Meta.Args {
				if ctx.do(ctx.call.Args[j], field.Name, fmt.Sprintf("call%v", i)) {
					goto again
				}
			}
			p0 = minimizeCallProps(p0, i, callIndex0, pred)
		}
	}

	if callIndex0 != -1 {
		if callIndex0 < 0 || callIndex0 >= len(p0.Calls) || name0 != p0.Calls[callIndex0].Meta.Name {
			panic(fmt.Sprintf("bad call index after minimization: ncalls=%v index=%v call=%v/%v",
				len(p0.Calls), callIndex0, name0, p0.Calls[callIndex0].Meta.Name))
		}
	}
	return p0, callIndex0
}

func RemoveUnrelatedCalls(p0 *Prog, callIndex0 int, pred minimizePred, processedCallsIn map[int]bool) (*Prog, int, map[int]bool) {
	var processedCalls map[int]bool
	if callIndex0 >= 0 && callIndex0+2 < len(p0.Calls) {
		// It's frequently the case that all subsequent calls were not necessary.
		// Try to drop them all at once.
		p := p0.Clone()
		for i := len(p0.Calls) - 1; i > callIndex0; i-- {
			p.RemoveCall(i)
		}
		if pred(p, callIndex0, statMinRemoveCall, "trailing calls") {
			p0 = p
		}
	}

	if callIndex0 != -1 {
		p0, callIndex0, processedCalls = removeUnrelatedCallsInfo(p0, callIndex0, pred, processedCallsIn)
	}

	return p0, callIndex0, processedCalls
}

func RemoveUnrelatedCallsFast(p0 *Prog, callIndex0 int, pred minimizePred, processedCallsIn []bool, c *Cache, resChanges []int) (*Prog, []bool) {
	var processedCalls []bool
	if callIndex0 >= 0 && callIndex0+2 < len(p0.Calls) {
		// It's frequently the case that all subsequent calls were not necessary.
		// Try to drop them all at once.
		p := p0.CloneUpTo(callIndex0)
		for i := len(p0.Calls) - 1; i > callIndex0; i-- {
			p.RemoveCall(i)
		}
		if pred(p, callIndex0, statMinRemoveCall, "trailing calls") {
			p0 = p
		}
	}

	if callIndex0 != -1 {
		p0, processedCalls = removeUnrelatedCallsInfoFast(p0, callIndex0, pred, processedCallsIn, c, resChanges)
	}

	return p0, processedCalls
}

type minimizePred func(*Prog, int, *stat.Val, string) bool

func removeCalls(p0 *Prog, callIndex0 int, pred minimizePred) (*Prog, int) {
	if callIndex0 >= 0 && callIndex0+2 < len(p0.Calls) {
		// It's frequently the case that all subsequent calls were not necessary.
		// Try to drop them all at once.
		p := p0.Clone()
		for i := len(p0.Calls) - 1; i > callIndex0; i-- {
			p.RemoveCall(i)
		}
		if pred(p, callIndex0, statMinRemoveCall, "trailing calls") {
			p0 = p
		}
	}

	if callIndex0 != -1 {
		p0, callIndex0 = removeUnrelatedCalls(p0, callIndex0, pred)
	}

	for i := len(p0.Calls) - 1; i >= 0; i-- {
		if i == callIndex0 {
			continue
		}
		callIndex := callIndex0
		if i < callIndex {
			callIndex--
		}
		p := p0.Clone()
		p.RemoveCall(i)
		if !pred(p, callIndex, statMinRemoveCall, fmt.Sprintf("call %v", i)) {
			continue
		}
		p0 = p
		callIndex0 = callIndex
	}
	return p0, callIndex0
}

func removeUnrelatedCallsInfo(p0 *Prog, callIndex0 int, pred minimizePred, processedCallsIn map[int]bool) (*Prog, int, map[int]bool) {
	keepCalls := relatedCalls(p0, callIndex0)
	if len(p0.Calls)-len(keepCalls) < 3 {
		return p0, callIndex0, processedCallsIn
	}
	p, callIndex := p0.Clone(), callIndex0
	for i := len(p0.Calls) - 1; i >= 0; i-- {
		if keepCalls[i] {
			continue
		}
		p.RemoveCall(i)
		if i < callIndex {
			callIndex--
		}
	}
	if !pred(p, callIndex, statMinRemoveCall, "unrelated calls") {
		return p0, callIndex0, processedCallsIn
	}
	processedCalls := mapsor(processedCallsIn, keepCalls)
	return p, callIndex, processedCalls
}

func cardinality(a []bool) int {
	ret := 0
	for _, b := range a {
		if b {
			ret++
		}
	}
	return ret
}

func removeUnrelatedCallsInfoFast(p0 *Prog, callIndex0 int, pred minimizePred, processedCallsIn []bool, c *Cache, resChanges []int) (*Prog, []bool) {
	keepCalls := relatedCallsWithCacheAndBloom(p0, callIndex0, c, resChanges, processedCallsIn)

	if len(p0.Calls)-cardinality(keepCalls) < 3 {
		return p0, processedCallsIn
	}
	p := p0.CloneFilter(keepCalls)

	processedCalls := sliceor(processedCallsIn, keepCalls)
	return p, processedCalls
}

// removeUnrelatedCalls tries to remove all "unrelated" calls at once.
// Unrelated calls are the calls that don't use any resources/files from
// the transitive closure of the resources/files used by the target call.
// This may significantly reduce large generated programs in a single step.
func removeUnrelatedCalls(p0 *Prog, callIndex0 int, pred minimizePred) (*Prog, int) {
	keepCalls := relatedCalls(p0, callIndex0)
	if len(p0.Calls)-len(keepCalls) < 3 {
		return p0, callIndex0
	}
	p, callIndex := p0.Clone(), callIndex0
	for i := len(p0.Calls) - 1; i >= 0; i-- {
		if keepCalls[i] {
			continue
		}
		p.RemoveCall(i)
		if i < callIndex {
			callIndex--
		}
	}
	if !pred(p, callIndex, statMinRemoveCall, "unrelated calls") {
		return p0, callIndex0
	}
	return p, callIndex
}

func relatedCalls(p0 *Prog, callIndex0 int) map[int]bool {
	keepCalls := map[int]bool{callIndex0: true}
	used := uses(p0.Calls[callIndex0])
	for {
		n := len(used)
		for i, call := range p0.Calls {
			if keepCalls[i] {
				continue
			}
			used1 := uses(call)
			if intersects(used1, used) {
				keepCalls[i] = true
				for what := range used1 {
					used[what] = true
				}
			}
		}
		if n == len(used) {
			return keepCalls
		}
	}
}

func relatedCallsWithCacheAndBloom(p0 *Prog, callIndex0 int, c *Cache, resChanges []int, processedCallsIn []bool) []bool {
	keepCalls := make([]bool, len(p0.Calls))
	keepCalls[callIndex0] = true
	usedBF := usesBF(p0.Calls[callIndex0], callIndex0, c)
	used := usesCache(p0.Calls[callIndex0], callIndex0, c)

	nextResChange := 0
	nextResChangeIdx := 0
	numCalls := len(p0.Calls)

	for {
		n := len(used)
		nextResChange = 0
		nextResChangeIdx = 0
		for i := 0; i < numCalls; i++ {
			if keepCalls[i] || processedCallsIn[i] {
				continue
			}

			call := p0.Calls[i]
			usedBF1 := usesBF(call, i, c)
			if intersectBFs(usedBF, usedBF1) {
				used1 := usesCache(call, i, c)
				if intersects(used, used1) {
					// fmt.Fprintf(os.Stderr, "Found an intersection %d\n", i)
					keepCalls[i] = true
					usedBF.Merge(usedBF1)
					for what := range used1 {
						used[what] = true
					}
				}
			} else {
				// jump up to next index with new FDs
				for len(resChanges) > nextResChangeIdx+1 && resChanges[nextResChangeIdx] <= i {
					nextResChangeIdx++
					nextResChange = resChanges[nextResChangeIdx]
				}
				if nextResChange > i {
					i = nextResChange - 1
				}
			}
		}
		if n == len(used) {
			return keepCalls
		}
		// // update resChanges to remove keepCalls && processedCallsIn
		numResChanges := len(resChanges)
		for i := numResChanges - 1; i >= 0; i-- {
			if processedCallsIn[resChanges[i]] || keepCalls[resChanges[i]] {
				if i == numResChanges-1 {
					resChanges = resChanges[:i]
				} else {
					resChanges = append(resChanges[:i], resChanges[i+1:]...)
				}
			}
		}
	}
}

func usesToNewBloom(uses map[any](bool)) *bloom.BloomFilter {
	bf := bloom.NewWithEstimates(500, 1)
	for what := range uses {
		switch what := what.(type) {
		case *ResultArg:
			bf.Add(ptrToBA(what))
		case string:
			bf.AddString(what)
		default:
			panic(fmt.Sprintf("Unclear how to convert %#v into []byte to add it to BloomFilter.\n", what))
		}
	}
	return bf
}

func usesBF(call *Call, i int, c *Cache) *bloom.BloomFilter {
	ret := c.Bfs[i]
	if ret == nil {
		uses := usesCache(call, i, c)
		bf := usesToNewBloom(uses)
		c.Bfs[i] = bf
		ret = bf
	}
	return ret
}

func usesCache(call *Call, i int, c *Cache) map[any]bool {
	ret := c.Uses[i]
	if ret == nil {
		ret = uses(call)
		c.Uses[i] = ret
		return ret
	}
	return ret
}

func ptrToBA[T any](p *T) []byte {
	return []byte(fmt.Sprintf("%p", p))
}

func uses(call *Call) map[any]bool {
	used := make(map[any]bool)
	ForeachArg(call, func(arg Arg, _ *ArgCtx) {
		switch typ := arg.Type().(type) {
		case *ResourceType:
			a := arg.(*ResultArg)
			used[a] = true
			if a.Res != nil {
				used[a.Res] = true
			}
			for use := range a.uses {
				used[use] = true
			}
		case *BufferType:
			a := arg.(*DataArg)
			if a.Dir() != DirOut && typ.Kind == BufferFilename {
				val := string(bytes.TrimRight(a.Data(), "\x00"))
				used[val] = true
			}
		}
	})
	return used
}

func intersects(list, list1 map[any]bool) bool {
	for what := range list1 {
		if list[what] {
			return true
		}
	}
	return false
}

func intersectBFs(bf1 *bloom.BloomFilter, bf2 *bloom.BloomFilter) bool {
	if bf1.BitSet().IntersectionCardinality(bf2.BitSet()) > 0 {
		return true
	}
	return false
}

func sliceor(list []bool, list1 []bool) []bool {
	if len(list) > len(list1) {
		for what := range list1 {
			if list1[what] {
				list[what] = true
			}
		}
		return list
	}
	for what := range list {
		if list[what] {
			list1[what] = true
		}
	}
	return list1
}

func mapsor(list map[int]bool, list1 map[int]bool) map[int]bool {
	for what := range list1 {
		if list1[what] {
			list[what] = true
		}
	}
	return list
}

func resetCallProps(p0 *Prog, callIndex0 int, pred minimizePred) *Prog {
	// Try to reset all call props to their default values.
	// This should be reasonable for many progs.
	p := p0.Clone()
	anyDifferent := false
	for idx := range p.Calls {
		if !reflect.DeepEqual(p.Calls[idx].Props, CallProps{}) {
			p.Calls[idx].Props = CallProps{}
			anyDifferent = true
		}
	}
	if anyDifferent && pred(p, callIndex0, statMinRemoveProps, "props") {
		return p
	}
	return p0
}

func minimizeCallProps(p0 *Prog, callIndex, callIndex0 int, pred minimizePred) *Prog {
	props := p0.Calls[callIndex].Props

	// Try to drop fault injection.
	if props.FailNth > 0 {
		p := p0.Clone()
		p.Calls[callIndex].Props.FailNth = 0
		if pred(p, callIndex0, statMinRemoveProps, "props") {
			p0 = p
		}
	}

	// Try to drop async.
	if props.Async {
		p := p0.Clone()
		p.Calls[callIndex].Props.Async = false
		if pred(p, callIndex0, statMinRemoveProps, "props") {
			p0 = p
		}
	}

	// Try to drop rerun.
	if props.Rerun > 0 {
		p := p0.Clone()
		p.Calls[callIndex].Props.Rerun = 0
		if pred(p, callIndex0, statMinRemoveProps, "props") {
			p0 = p
		}
	}

	return p0
}

type minimizeArgsCtx struct {
	target     *Target
	p0         **Prog
	p          *Prog
	call       *Call
	callIndex0 int
	mode       MinimizeMode
	pred       minimizePred
	triedPaths map[string]bool
}

func (ctx *minimizeArgsCtx) do(arg Arg, field, path string) bool {
	path += fmt.Sprintf("-%v", field)
	if ctx.triedPaths[path] {
		return false
	}
	p0 := *ctx.p0
	if arg.Type().minimize(ctx, arg, path) {
		return true
	}
	if *ctx.p0 == ctx.p {
		// If minimize committed a new program, it must return true.
		// Otherwise *ctx.p0 and ctx.p will point to the same program
		// and any temp mutations to ctx.p will unintentionally affect ctx.p0.
		panic("shared program committed")
	}
	if *ctx.p0 != p0 {
		// New program was committed, but we did not start iteration anew.
		// This means we are iterating over a stale tree and any changes won't be visible.
		panic("iterating over stale program")
	}
	ctx.triedPaths[path] = true
	return false
}

func (typ *TypeCommon) minimize(ctx *minimizeArgsCtx, arg Arg, path string) bool {
	return false
}

func (typ *StructType) minimize(ctx *minimizeArgsCtx, arg Arg, path string) bool {
	a := arg.(*GroupArg)
	for i, innerArg := range a.Inner {
		if ctx.do(innerArg, typ.Fields[i].Name, path) {
			return true
		}
	}
	return false
}

func (typ *UnionType) minimize(ctx *minimizeArgsCtx, arg Arg, path string) bool {
	a := arg.(*UnionArg)
	return ctx.do(a.Option, typ.Fields[a.Index].Name, path)
}

func (typ *PtrType) minimize(ctx *minimizeArgsCtx, arg Arg, path string) bool {
	a := arg.(*PointerArg)
	if a.Res == nil {
		return false
	}
	if path1 := path + ">"; !ctx.triedPaths[path1] {
		removeArg(a.Res)
		replaceArg(a, MakeSpecialPointerArg(a.Type(), a.Dir(), 0))
		ctx.target.assignSizesCall(ctx.call)
		if ctx.pred(ctx.p, ctx.callIndex0, statMinPtr, path1) {
			*ctx.p0 = ctx.p
		}
		ctx.triedPaths[path1] = true
		return true
	}
	return ctx.do(a.Res, "", path)
}

func (typ *ArrayType) minimize(ctx *minimizeArgsCtx, arg Arg, path string) bool {
	a := arg.(*GroupArg)
	// If there are at least 3 elements, try to remove all at once first.
	// If will be faster than removing them one-by-one if all of them are not needed.
	if allPath := path + "-all"; len(a.Inner) >= 3 && typ.RangeBegin == 0 && !ctx.triedPaths[allPath] {
		ctx.triedPaths[allPath] = true
		for _, elem := range a.Inner {
			removeArg(elem)
		}
		a.Inner = nil
		ctx.target.assignSizesCall(ctx.call)
		if ctx.pred(ctx.p, ctx.callIndex0, statMinArray, allPath) {
			*ctx.p0 = ctx.p
		}
		return true
	}
	// Try to remove individual elements one-by-one.
	for i := len(a.Inner) - 1; i >= 0; i-- {
		elem := a.Inner[i]
		elemPath := fmt.Sprintf("%v-%v", path, i)
		if ctx.mode != MinimizeCrash && !ctx.triedPaths[elemPath] &&
			(typ.Kind == ArrayRandLen ||
				typ.Kind == ArrayRangeLen && uint64(len(a.Inner)) > typ.RangeBegin) {
			ctx.triedPaths[elemPath] = true
			copy(a.Inner[i:], a.Inner[i+1:])
			a.Inner = a.Inner[:len(a.Inner)-1]
			removeArg(elem)
			ctx.target.assignSizesCall(ctx.call)
			if ctx.pred(ctx.p, ctx.callIndex0, statMinArray, elemPath) {
				*ctx.p0 = ctx.p
			}
			return true
		}
		if ctx.do(elem, "", elemPath) {
			return true
		}
	}
	return false
}

func (typ *IntType) minimize(ctx *minimizeArgsCtx, arg Arg, path string) bool {
	return minimizeInt(ctx, arg, path)
}

func (typ *FlagsType) minimize(ctx *minimizeArgsCtx, arg Arg, path string) bool {
	return minimizeInt(ctx, arg, path)
}

func (typ *ProcType) minimize(ctx *minimizeArgsCtx, arg Arg, path string) bool {
	if !typ.Optional() {
		// Default value for ProcType is 0 (same for all PID's).
		// Usually 0 either does not make sense at all or make different PIDs collide
		// (since we use ProcType to separate value ranges for different PIDs).
		// So don't change ProcType to 0 unless the type is explicitly marked as opt
		// (in that case we will also generate 0 anyway).
		return false
	}
	return minimizeInt(ctx, arg, path)
}

func minimizeInt(ctx *minimizeArgsCtx, arg Arg, path string) bool {
	if ctx.mode != MinimizeCrashSnapshot {
		return false
	}
	a := arg.(*ConstArg)
	def := arg.Type().DefaultArg(arg.Dir()).(*ConstArg)
	if a.Val == def.Val {
		return false
	}
	v0 := a.Val
	a.Val = def.Val

	// By mutating an integer, we risk violating conditional fields.
	// If the fields are patched, the minimization process must be restarted.
	patched := ctx.call.setDefaultConditions(ctx.p.Target, false)
	if ctx.pred(ctx.p, ctx.callIndex0, statMinInt, path) {
		*ctx.p0 = ctx.p
		ctx.triedPaths[path] = true
		return true
	}
	a.Val = v0
	if patched {
		// No sense to return here.
		ctx.triedPaths[path] = true
	}
	return patched
}

func (typ *ResourceType) minimize(ctx *minimizeArgsCtx, arg Arg, path string) bool {
	if ctx.mode != MinimizeCrashSnapshot {
		return false
	}
	a := arg.(*ResultArg)
	if a.Res == nil {
		return false
	}
	r0 := a.Res
	delete(a.Res.uses, a)
	a.Res, a.Val = nil, typ.Default()
	if ctx.pred(ctx.p, ctx.callIndex0, statMinResource, path) {
		*ctx.p0 = ctx.p
	} else {
		a.Res, a.Val = r0, 0
		a.Res.uses[a] = true
	}
	ctx.triedPaths[path] = true
	return true
}

func (typ *BufferType) minimize(ctx *minimizeArgsCtx, arg Arg, path string) bool {
	if arg.Dir() == DirOut {
		return false
	}
	if typ.IsCompressed() {
		panic(fmt.Sprintf("minimizing `no_minimize` call %v", ctx.call.Meta.Name))
	}
	a := arg.(*DataArg)
	switch typ.Kind {
	case BufferBlobRand, BufferBlobRange:
		len0 := len(a.Data())
		minLen := int(typ.RangeBegin)
		for step := len(a.Data()) - minLen; len(a.Data()) > minLen && step > 0; {
			if len(a.Data())-step >= minLen {
				a.data = a.Data()[:len(a.Data())-step]
				ctx.target.assignSizesCall(ctx.call)
				if ctx.pred(ctx.p, ctx.callIndex0, statMinBuffer, path) {
					step /= 2
					continue
				}
				a.data = a.Data()[:len(a.Data())+step]
				ctx.target.assignSizesCall(ctx.call)
			}
			step /= 2
			if ctx.mode == MinimizeCrash {
				break
			}
		}
		if len(a.Data()) != len0 {
			*ctx.p0 = ctx.p
			ctx.triedPaths[path] = true
			return true
		}
	case BufferFilename:
		if ctx.mode == MinimizeCorpus {
			return false
		}
		// Try to undo target.SpecialFileLenghts mutation
		// and reduce file name length.
		if !typ.Varlen() {
			return false
		}
		data0 := append([]byte{}, a.Data()...)
		a.data = bytes.TrimRight(a.Data(), specialFileLenPad+"\x00")
		if !typ.NoZ {
			a.data = append(a.data, 0)
		}
		if bytes.Equal(a.data, data0) {
			return false
		}
		ctx.target.assignSizesCall(ctx.call)
		if ctx.pred(ctx.p, ctx.callIndex0, statMinFilename, path) {
			*ctx.p0 = ctx.p
		}
		ctx.triedPaths[path] = true
		return true
	}
	return false
}
