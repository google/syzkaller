// Copyright 2015/2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"cmp"
	"fmt"
	"maps"
	"math"
	"math/rand"
	"slices"
	"sort"
	"strings"
)

// Calculation of syscall choice tables.
//
// When adding a call to a program after a given (bias) call, ChoiceTable combines
// static type analysis and dynamic corpus history:
//
//  1. Static (callTags -> tagCalls): calcResourceUsage assigns each shared resource/type a tag:
//     - resources and their supertypes (e.g. "res-fd", "res-fd-sock", "res-fd-sock-sock_in"),
//     - pointers to structs/unions/arrays (e.g. "ptrto-sockaddr_in", "ptrto-msghdr"),
//     - strings with subkinds (e.g. "str-filesystem"), "filename", and "vma".
//     Instead of an O(N^2) call-to-call matrix, callTags[callID] maps a call to its tags
//     (weighted toward outputs and scaled by capped sqrt(tagSum) so huge tags like "res-fd"
//     don't drown out specific ones), and tagCalls[tagID] maps a tag to its consumer calls
//     (weighted toward inputs). Static selection walks callID -> tagID -> targetCallID.
//
//  2. Dynamic (dynamicCalls): dynamicCalls[callID] lists syscalls that appear after callID
//     in corpus programs, weighted by sqrt(number of such programs).

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
				var str strings.Builder
				str.WriteString("res")
				for i, k := range a.Desc.Kind {
					str.WriteString("-" + k)
					w := int32(10)
					if i < len(a.Desc.Kind)-1 {
						w = 2
					}
					noteUsage(uses, c, w, ctx.Dir, str.String())
				}
			}
		case *PtrType:
			switch elem := a.Elem.(type) {
			case *StructType, *UnionType:
				noteUsagef(uses, c, 4, ctx.Dir, "ptrto-%v", elem.Name())
			case *ArrayType:
				noteUsagef(uses, c, 4, ctx.Dir, "ptrto-%v", elem.Elem.Name())
			}
		case *BufferType:
			switch a.Kind {
			case BufferBlobRand, BufferBlobRange, BufferText, BufferCompressed:
			case BufferString, BufferGlob:
				if a.SubKind != "" {
					noteUsagef(uses, c, 2, ctx.Dir, "str-%v", a.SubKind)
				}
			case BufferFilename:
				noteUsage(uses, c, 10, DirIn, tagFilename)
			default:
				panic("unknown buffer kind")
			}
		case *VmaType:
			noteUsage(uses, c, 5, ctx.Dir, tagVma)
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
	out   int32
	inout int32
}

func noteUsage(uses map[string]map[int]weights, c *Syscall, weight int32, dir Dir, id string) {
	if uses[id] == nil {
		uses[id] = make(map[int]weights)
	}
	callWeight := uses[id][c.ID]
	callWeight.call = c.ID
	if dir != DirOut {
		callWeight.in = max(callWeight.in, weight)
	}
	if dir != DirIn {
		callWeight.out = max(callWeight.out, weight)
	}
	callWeight.inout = max(callWeight.inout, weight)
	uses[id][c.ID] = callWeight
}

func noteUsagef(uses map[string]map[int]weights, c *Syscall, weight int32, dir Dir, str string, args ...any) {
	noteUsage(uses, c, weight, dir, fmt.Sprintf(str, args...))
}

// Generic tags that connect lots of unrelated calls.
const (
	tagFilename = "filename"
	tagVma      = "vma"
)

// Tuning constants of the static/dynamic choice heuristics.
// Note: there is no theory behind any of them.
const (
	// Weight of a tag for a call that uses it in the "right" direction relative
	// to a call that only uses it in the other direction: producers (out) are
	// preferred when weighting the tags of the bias call, and consumers (in) are
	// preferred when choosing the next call for a tag.
	tagDirWeight = 3
	// Cap on tagSum inside sqrt(tagSum) so huge hub tags (like fd with 7000+ calls)
	// don't drown out specific resource tags while 2-call tags don't monopolize choices.
	maxStaticTagSumScale = 2500
	// Multiplier of sqrt(count) in the dynamic (corpus co-occurrence) weights.
	dynamicCountScale = 2.0
	// Probability (in %) to choose the next call from the dynamic table is
	// dynamicPercentPerCall * (number of distinct calls that followed the bias call
	// in the corpus), capped at maxDynamicPercent. So a call that was seen with
	// a single other call doesn't hand 50% of all choices to that call.
	dynamicPercentPerCall = 15
	maxDynamicPercent     = 50
	// Static selection retries up to selfLoopRetries times if it picks the bias
	// call itself, accepting the self-loop with 1/selfLoopAcceptOneOf probability
	// on each retry, so narrow 2-call tags don't mostly pick the bias call.
	selfLoopRetries     = 4
	selfLoopAcceptOneOf = 4
)

type prioItem struct {
	id     int
	cumSum int32
}

// prioList is a weighted list of IDs stored with cumulative weights for O(log N) sampling.
// The table fields of ChoiceTable (callTags, tagCalls, dynamicCalls) keep the lists
// sorted by id, which allows binary search and merge scans by id. Temporary lists of
// sampled candidates are not sorted and may contain duplicates.
type prioList []prioItem

func (pl *prioList) add(id int, weight int32) {
	if weight <= 0 {
		return
	}
	*pl = append(*pl, prioItem{id: id, cumSum: pl.total() + weight})
}

func (pl *prioList) total() int32 {
	if len(*pl) == 0 {
		return 0
	}
	return (*pl)[len(*pl)-1].cumSum
}

func (pl *prioList) itemWeight(idx int) int32 {
	if idx == 0 {
		return (*pl)[0].cumSum
	}
	return (*pl)[idx].cumSum - (*pl)[idx-1].cumSum
}

func (pl *prioList) sample(r *rand.Rand) int {
	x := int32(r.Intn(int(pl.total())) + 1)
	idx := sort.Search(len(*pl), func(i int) bool {
		return (*pl)[i].cumSum >= x
	})
	return (*pl)[idx].id
}

// ChoiceTable allows making a weighted choice of a syscall for a given syscall
// based on static resource/type priorities and dynamic corpus colocation.
type ChoiceTable struct {
	target      *Target
	calls       []*Syscall
	generatable []bool

	// Bipartite static priority table built from calcResourceUsage tags
	// (e.g. "res-fd-sock", "ptrto-sockaddr_in", "str-filesystem", "filename", "vma"):
	// callTags[callID] stores the tagIDs used by callID and their cumulative weights.
	// tagCalls[tagID] stores the consumer callIDs for tagID and their cumulative weights.
	callTags []prioList
	tagCalls []prioList

	// Sparse dynamic priority table:
	// dynamicCalls[callID] stores the syscalls that appear after callID in the corpus,
	// sorted by id, with cumulative sqrt(count) weights.
	dynamicCalls []prioList
}

func (target *Target) BuildChoiceTable(corpus []*Prog, enabled map[*Syscall]bool) *ChoiceTable {
	enabledCalls := target.prepareEnabledSyscalls(corpus, enabled)
	ct := &ChoiceTable{
		target:      target,
		calls:       slices.Collect(maps.Keys(enabledCalls)),
		generatable: make([]bool, len(target.Syscalls)),
	}
	slices.SortFunc(ct.calls, func(a, b *Syscall) int {
		return cmp.Compare(a.ID, b.ID)
	})
	for _, c := range ct.calls {
		ct.generatable[c.ID] = true
	}
	ct.buildStaticPriorities(enabledCalls)
	ct.buildDynamicPriorities(corpus)
	return ct
}

func (ct *ChoiceTable) buildStaticPriorities(enabled map[*Syscall]bool) {
	uses := ct.target.calcResourceUsage(enabled)
	tagNames := slices.Sorted(maps.Keys(uses))
	ct.callTags = make([]prioList, len(ct.target.Syscalls))
	ct.tagCalls = make([]prioList, 0, len(tagNames))

	for _, tag := range tagNames {
		weightMap := uses[tag]
		if len(weightMap) < 2 {
			// A tag used by only a single syscall does not connect it to any other syscall.
			continue
		}
		callWeights := slices.Collect(maps.Values(weightMap))
		slices.SortFunc(callWeights, func(a, b weights) int {
			return cmp.Compare(a.call, b.call)
		})

		tagID := len(ct.tagCalls)
		var consumers prioList
		for _, w := range callWeights {
			// Higher priority when the target call uses the resource as an input.
			consumers.add(w.call, w.in*tagDirWeight+w.inout)
		}
		ct.tagCalls = append(ct.tagCalls, consumers)

		// Weight the tag by (tagDirWeight*out + in) * sqrt(min(tagSum, maxStaticTagSumScale)) so
		// resources produced by the bias call are preferred over resources it only consumes,
		// without letting huge generic tags (like fd) drown out specific subkinds.
		tagScale := max(1, int32(math.Sqrt(float64(min(consumers.total(), maxStaticTagSumScale)))))
		for _, w := range callWeights {
			ct.callTags[w.call].add(tagID, (w.out*tagDirWeight+w.in)*tagScale)
		}
	}
}

func (ct *ChoiceTable) buildDynamicPriorities(corpus []*Prog) {
	ct.dynamicCalls = make([]prioList, len(ct.target.Syscalls))
	pairCounts := make(map[int]map[int]int)
	for _, p := range corpus {
		var ids []int
		for _, c := range p.Calls {
			if ct.Generatable(c.Meta.ID) {
				ids = append(ids, c.Meta.ID)
			}
		}
		for i, id0 := range ids {
			if slices.Contains(ids[:i], id0) {
				continue
			}
			if pairCounts[id0] == nil {
				pairCounts[id0] = make(map[int]int)
			}
			for j := i + 1; j < len(ids); j++ {
				// Count each ordered pair (id0, id1) at most once per corpus program.
				if id1 := ids[j]; !slices.Contains(ids[i+1:j], id1) {
					pairCounts[id0][id1]++
				}
			}
		}
	}
	for id0, counts := range pairCounts {
		var row prioList
		for _, id1 := range slices.Sorted(maps.Keys(counts)) {
			// It's more important that some calls do coexist than whether
			// it happened 50 or 100 times, so use sqrt() to lessen the effect of large counts.
			row.add(id1, max(1, int32(dynamicCountScale*math.Sqrt(float64(counts[id1])))))
		}
		ct.dynamicCalls[id0] = row
	}
}

func (ct *ChoiceTable) Generatable(call int) bool {
	return call >= 0 && call < len(ct.generatable) && ct.generatable[call]
}

// StaticPriorities returns the static two-hop transition probabilities from call
// to all syscalls in the target. It's only used for debugging/UI (syz-showprio and
// the /prio page), fuzzing uses the sampling methods below.
func (ct *ChoiceTable) StaticPriorities(call *Syscall) []float64 {
	probs := make([]float64, len(ct.target.Syscalls))
	tags := ct.callTags[call.ID]
	if len(tags) == 0 {
		return probs
	}
	totalTag := float64(tags.total())
	for i, tag := range tags {
		tagProb := float64(tags.itemWeight(i)) / totalTag
		consumers := ct.tagCalls[tag.id]
		totalCall := float64(consumers.total())
		for j, consumer := range consumers {
			probs[consumer.id] += tagProb * float64(consumers.itemWeight(j)) / totalCall
		}
	}
	return probs
}

// randomCall returns a uniformly random generatable call.
func (ct *ChoiceTable) randomCall(r *rand.Rand) int {
	return ct.calls[r.Intn(len(ct.calls))].ID
}

func (ct *ChoiceTable) choose(r *rand.Rand, bias int) int {
	if r.Intn(100) < 5 {
		// Let's make 5% decisions totally at random.
		return ct.randomCall(r)
	}
	if bias < 0 {
		bias = ct.randomCall(r)
	} else if !ct.Generatable(bias) {
		fmt.Printf("bias to disabled or non-generatable syscall %v\n", ct.target.Syscalls[bias].Name)
		panic("disabled or non-generatable syscall")
	}
	var res int
	row := ct.dynamicCalls[bias]
	if dynProb := min(maxDynamicPercent, dynamicPercentPerCall*len(row)); r.Intn(100) < dynProb {
		res = row.sample(r)
	} else {
		res = ct.chooseStaticSingle(r, bias)
	}
	if !ct.Generatable(res) {
		panic("selected disabled or non-generatable syscall")
	}
	return res
}

// chooseStaticSingle chooses the next call based on the static priorities of a single bias call.
func (ct *ChoiceTable) chooseStaticSingle(r *rand.Rand, bias int) int {
	tags := ct.callTags[bias]
	if len(tags) == 0 {
		return ct.randomCall(r)
	}
	// Two-hop walk on the bipartite static graph (call -> tag -> consumer call).
	for range selfLoopRetries {
		tagID := tags.sample(r)
		if res := ct.tagCalls[tagID].sample(r); res != bias || r.Intn(selfLoopAcceptOneOf) == 0 {
			return res
		}
	}
	return bias
}
