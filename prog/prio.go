// Copyright 2015/2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"fmt"
	"math"
	"math/rand"
	"slices"
	"sort"
)

// Calulation of call-to-call priorities.
// For a given pair of calls X and Y, the priority is our guess as to whether
// additional of call Y into a program containing call X is likely to give
// new coverage or not.
// The current algorithm has two components: static and dynamic.
// The static component is based on analysis of argument types. For example,
// if call X and call Y both accept fd[sock], then they are more likely to give
// new coverage together.
// The dynamic component is based on frequency of occurrence of a particular
// pair of syscalls in a single program in corpus. For example, if socket and
// connect frequently occur in programs together, we give higher priority to
// this pair of syscalls.
// Note: the current implementation is very basic, there is no theory behind any
// constants.

// CalculatePriorities returns the priority matrix as well as the map of generatable syscalls.
// The rows/columns corresponding to the non-generatable syscalls are left to be 0.
func (target *Target) CalculatePriorities(corpus []*Prog, enabled map[*Syscall]bool) ([][]int32, map[*Syscall]bool) {
	enabled = target.prepareEnabledSyscalls(corpus, enabled)
	static := target.calcStaticPriorities(enabled)
	if len(corpus) != 0 {
		// Let's just sum the static and dynamic distributions.
		dynamic := target.calcDynamicPrio(corpus, enabled)
		for i, prios := range dynamic {
			dst := static[i]
			for j, p := range prios {
				dst[j] += p
			}
		}
	}
	if debug {
		for _, syscall := range target.Syscalls {
			if enabled[syscall] {
				continue
			}
			for i := range static {
				if static[i][syscall.ID] != 0 || static[syscall.ID][i] != 0 {
					panic(fmt.Sprintf("prio matrix has non-zero value for a disabled syscall %d",
						syscall.ID))
				}
			}
		}
	}
	return static, enabled
}

func (target *Target) prepareEnabledSyscalls(corpus []*Prog, enabled map[*Syscall]bool) map[*Syscall]bool {
	if enabled == nil {
		enabled = make(map[*Syscall]bool)
		for _, c := range target.Syscalls {
			enabled[c] = true
		}
	}
	noGenerateCalls := make(map[int]bool)
	enabledCalls := make(map[*Syscall]bool)
	for call := range enabled {
		if call.Attrs.NoGenerate {
			noGenerateCalls[call.ID] = true
		} else if !call.Attrs.Disabled {
			enabledCalls[call] = true
		}
	}
	// Some validation checks.
	if len(enabledCalls) == 0 {
		panic("no syscalls enabled and generatable")
	}
	for _, p := range corpus {
		for _, call := range p.Calls {
			if !enabledCalls[call.Meta] && !noGenerateCalls[call.Meta.ID] {
				fmt.Printf("corpus contains disabled syscall %v\n", call.Meta.Name)
				for call := range enabled {
					fmt.Printf("%s: enabled\n", call.Name)
				}
				panic("disabled syscall")
			}
		}
	}
	return enabledCalls
}

func (target *Target) calcStaticPriorities(enabled map[*Syscall]bool) [][]int32 {
	uses := target.calcResourceUsage(enabled)
	prios := make([][]int32, len(target.Syscalls))
	for i := range prios {
		prios[i] = make([]int32, len(target.Syscalls))
	}
	for _, weights := range uses {
		for _, w0 := range weights {
			for _, w1 := range weights {
				if w0.call == w1.call {
					// Self-priority is assigned below.
					continue
				}
				// The static priority is assigned based on the direction of arguments. A higher priority will be
				// assigned when c0 is a call that produces a resource and c1 a call that uses that resource.
				prios[w0.call][w1.call] += w0.inout*w1.in*3/2 + w0.inout*w1.inout
			}
		}
	}
	// The value assigned for self-priority (call wrt itself) have to be high, but not too high.
	for c := range enabled {
		id, pp := c.ID, prios[c.ID]
		max := slices.Max(pp)
		if max == 0 {
			pp[id] = 1
		} else {
			pp[id] = max * 3 / 4
		}
	}
	normalizePrios(prios, len(enabled))
	return prios
}

func (target *Target) calcResourceUsage(enabled map[*Syscall]bool) map[string]map[int]weights {
	uses := make(map[string]map[int]weights)
	ForeachType(target.Syscalls, func(t Type, ctx *TypeCtx) {
		c := ctx.Meta
		if !enabled[c] {
			ctx.Stop = true
			return
		}
		switch a := t.(type) {
		case *ResourceType:
			if target.AuxResources[a.Desc.Name] {
				noteUsagef(uses, c, 1, ctx.Dir, "res%v", a.Desc.Name)
			} else {
				str := "res"
				for i, k := range a.Desc.Kind {
					str += "-" + k
					w := int32(10)
					if i < len(a.Desc.Kind)-1 {
						w = 2
					}
					noteUsage(uses, c, w, ctx.Dir, str)
				}
			}
		case *PtrType:
			if _, ok := a.Elem.(*StructType); ok {
				noteUsagef(uses, c, 10, ctx.Dir, "ptrto-%v", a.Elem.Name())
			}
			if _, ok := a.Elem.(*UnionType); ok {
				noteUsagef(uses, c, 10, ctx.Dir, "ptrto-%v", a.Elem.Name())
			}
			if arr, ok := a.Elem.(*ArrayType); ok {
				noteUsagef(uses, c, 10, ctx.Dir, "ptrto-%v", arr.Elem.Name())
			}
		case *BufferType:
			switch a.Kind {
			case BufferBlobRand, BufferBlobRange, BufferText, BufferCompressed:
			case BufferString, BufferGlob:
				if a.SubKind != "" {
					noteUsagef(uses, c, 2, ctx.Dir, "str-%v", a.SubKind)
				}
			case BufferFilename:
				noteUsage(uses, c, 10, DirIn, "filename")
			default:
				panic("unknown buffer kind")
			}
		case *VmaType:
			noteUsage(uses, c, 5, ctx.Dir, "vma")
		case *IntType:
			switch a.Kind {
			case IntPlain, IntRange:
			default:
				panic("unknown int kind")
			}
		}
	})
	return uses
}

type weights struct {
	call  int
	in    int32
	inout int32
}

func noteUsage(uses map[string]map[int]weights, c *Syscall, weight int32, dir Dir, str string) {
	noteUsagef(uses, c, weight, dir, "%v", str)
}

func noteUsagef(uses map[string]map[int]weights, c *Syscall, weight int32, dir Dir, str string, args ...any) {
	id := fmt.Sprintf(str, args...)
	if uses[id] == nil {
		uses[id] = make(map[int]weights)
	}
	callWeight := uses[id][c.ID]
	callWeight.call = c.ID
	if dir != DirOut {
		if weight > uses[id][c.ID].in {
			callWeight.in = weight
		}
	}
	if weight > uses[id][c.ID].inout {
		callWeight.inout = weight
	}
	uses[id][c.ID] = callWeight
}

func (target *Target) calcDynamicPrio(corpus []*Prog, enabled map[*Syscall]bool) [][]int32 {
	prios := make([][]int32, len(target.Syscalls))
	for i := range prios {
		prios[i] = make([]int32, len(target.Syscalls))
	}
	for _, p := range corpus {
		for idx0, c0 := range p.Calls {
			if !enabled[c0.Meta] {
				continue
			}
			for _, c1 := range p.Calls[idx0+1:] {
				if !enabled[c1.Meta] {
					continue
				}
				prios[c0.Meta.ID][c1.Meta.ID]++
			}
		}
	}
	for i := range prios {
		for j, val := range prios[i] {
			// It's more important that some calls do coexist than whether
			// it happened 50 or 100 times.
			// Let's use sqrt() to lessen the effect of large counts.
			prios[i][j] = int32(2.0 * math.Sqrt(float64(val)))
		}
	}
	normalizePrios(prios, len(enabled))
	return prios
}

// normalizePrio distributes |N| * 10 points proportional to the values in the matrix.
// |N| is the number of the generatable syscalls.
func normalizePrios(prios [][]int32, n int) {
	total := 10 * int32(n)
	for _, prio := range prios {
		sum := int32(0)
		for _, p := range prio {
			sum += p
		}
		if sum == 0 {
			continue
		}
		for i, p := range prio {
			prio[i] = p * total / sum
		}
	}
}

// ChooseTable allows to do a weighted choice of a syscall for a given syscall
// based on call-to-call priorities and a set of enabled and generatable syscalls.
type ChoiceTable struct {
	target *Target
	runs   [][]int32
	calls  []*Syscall
}

func (target *Target) BuildChoiceTable(corpus []*Prog, enabled map[*Syscall]bool) *ChoiceTable {
	prios, enabledCalls := target.CalculatePriorities(corpus, enabled)
	var generatableCalls []*Syscall
	for c := range enabledCalls {
		generatableCalls = append(generatableCalls, c)
	}
	sort.Slice(generatableCalls, func(i, j int) bool {
		return generatableCalls[i].ID < generatableCalls[j].ID
	})

	run := make([][]int32, len(target.Syscalls))
	// ChoiceTable.runs[][] contains cumulated sum of weighted priority numbers.
	// This helps in quick binary search with biases when generating programs.
	// This only applies for system calls that are enabled for the target.
	for i := range run {
		if !enabledCalls[target.Syscalls[i]] {
			continue
		}
		run[i] = make([]int32, len(target.Syscalls))
		var sum int32
		for j := range run[i] {
			if enabledCalls[target.Syscalls[j]] {
				sum += prios[i][j]
			}
			run[i][j] = sum
		}
	}
	return &ChoiceTable{target, run, generatableCalls}
}

func (ct *ChoiceTable) Generatable(call int) bool {
	return ct.runs[call] != nil
}

func (ct *ChoiceTable) choose(r *rand.Rand, bias int) int {
	if r.Intn(100) < 5 {
		// Let's make 5% decisions totally at random.
		return ct.calls[r.Intn(len(ct.calls))].ID
	}
	if bias < 0 {
		bias = ct.calls[r.Intn(len(ct.calls))].ID
	}
	if !ct.Generatable(bias) {
		fmt.Printf("bias to disabled or non-generatable syscall %v\n", ct.target.Syscalls[bias].Name)
		panic("disabled or non-generatable syscall")
	}
	run := ct.runs[bias]
	runSum := int(run[len(run)-1])
	x := int32(r.Intn(runSum) + 1)
	res := sort.Search(len(run), func(i int) bool {
		return run[i] >= x
	})
	if !ct.Generatable(res) {
		panic("selected disabled or non-generatable syscall")
	}
	return res
}
