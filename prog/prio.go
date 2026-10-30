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
// When adding a call to a program (given a bias call or a prefix of preceding calls),
// ChoiceTable combines static type analysis and dynamic corpus history:
//
//  1. Static (callTags -> tagCalls): calcResourceUsage assigns each shared resource/type a tag:
//     - resources and their supertypes (e.g. "res-fd", "res-fd-sock", "res-fd-sock-sock_in"),
//     - pointers to structs/unions/arrays (e.g. "ptrto-sockaddr_in", "ptrto-msghdr"),
//     - strings with subkinds (e.g. "str-filesystem"), "filename", and "vma".
//     Instead of an O(N^2) matrix, callTags[callID] maps a call to its tags (weighted toward
//     outputs and scaled by capped sqrt(tagSum) so huge tags like "res-fd" don't drown out
//     specific ones), and tagCalls[tagID] maps a tag to its consumer calls (weighted toward
//     inputs). Static selection walks callID -> tagID -> targetCallID, and boosts candidates
//     that share specific tags (<= maxSpecificTagCalls) with multiple prefix calls.
//
//  2. Dynamic (dynamicCalls + callToProgs):
//     - dynamicCalls[callID] lists syscalls that appear after callID in corpus programs,
//     weighted by 2*sqrt(numPrograms).
//     - callToProgs[callID] lists multi-call corpus programs containing callID.
//     Given a multi-call prefix, chooseDynamic samples candidates in two ways:
//     (a) it inspects a few corpus programs containing the prefix's rarest, most recent, or
//     bias call; if a corpus program shares >= 2 calls with the prefix, it samples a call that
//     follows them in that program (preferring calls that appear in fewer corpus programs);
//     (b) it samples candidates from dynamicCalls and boosts those that follow multiple calls
//     in the prefix (with higher weight for more recent prefix calls).

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

const (
	// Cap on tagSum inside sqrt(tagSum) so huge hub tags (like fd with 7000+ calls)
	// don't drown out specific resource tags while 2-call tags don't monopolize choices.
	maxStaticTagSumScale = 2500
	// Maximum tag size considered specific when boosting multi-prefix resource consumers.
	maxSpecificTagCalls = 600
	// Maximum tag size used to associate unfocused corpus seeds with focused programs.
	maxRelatedTagCalls = 120
)

type prioItem struct {
	id     int
	cumSum int32
}

// prioList is a weighted list of IDs stored with cumulative weights for O(log N) sampling.
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

// relWeight returns id's share of the list's total weight in per-mille (1..1000), or 0 if absent.
func (pl *prioList) relWeight(id int) int32 {
	idx, ok := slices.BinarySearchFunc(*pl, id, func(item prioItem, id int) int {
		return cmp.Compare(item.id, id)
	})
	if !ok {
		return 0
	}
	return max(1, pl.itemWeight(idx)*1000/pl.total())
}

// ChoiceTable allows making a weighted choice of a syscall for a given syscall
// or program prefix based on static resource/type priorities and dynamic corpus colocation.
type ChoiceTable struct {
	target      *Target
	calls       []*Syscall
	generatable []bool

	// Bipartite static priority table built from calcResourceUsage tags
	// (e.g. "res-fd-sock", "ptrto-sockaddr_in", "str-filesystem", "filename", "vma"):
	// callTags[callID] stores the tagIDs used by callID and their cumulative weights.
	// tagCalls[tagID] stores the consumer callIDs for tagID and their cumulative weights.
	// minOutTagLen[callID] stores the smallest consumer count among tags produced by callID (0 if none).
	// specificTag[tagID] is true for non-generic tags with <= maxSpecificTagCalls consumers.
	callTags     []prioList
	tagCalls     []prioList
	minOutTagLen []int
	specificTag  []bool

	// Sparse dynamic priority table and corpus program index:
	// dynamicCalls[callID] stores the syscalls that appear after callID in the corpus,
	// sorted by id, with cumulative sqrt(count) weights.
	// callToProgs[callID] stores the multi-call corpus programs containing callID.
	dynamicCalls []prioList
	callToProgs  [][]*Prog
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
	ct.minOutTagLen = make([]int, len(ct.target.Syscalls))
	ct.specificTag = make([]bool, 0, len(tagNames))

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
			consumers.add(w.call, w.in*3+w.inout)
		}
		ct.tagCalls = append(ct.tagCalls, consumers)
		ct.specificTag = append(ct.specificTag,
			tag != "filename" && tag != "vma" && len(consumers) <= maxSpecificTagCalls)

		// Weight the tag by (3*out + 1*in) * sqrt(min(tagSum, maxStaticTagSumScale)) so
		// resources produced by the bias call are preferred over resources it only consumes,
		// without letting huge generic tags (like fd) drown out specific subkinds.
		tagScale := max(1, int32(math.Sqrt(float64(min(consumers.total(), maxStaticTagSumScale)))))
		for _, w := range callWeights {
			ct.callTags[w.call].add(tagID, (w.out*3+w.in)*tagScale)
			if w.out > 0 && (ct.minOutTagLen[w.call] == 0 || len(consumers) < ct.minOutTagLen[w.call]) {
				ct.minOutTagLen[w.call] = len(consumers)
			}
		}
	}
}

func (ct *ChoiceTable) buildDynamicPriorities(corpus []*Prog) {
	nCalls := len(ct.target.Syscalls)
	ct.dynamicCalls = make([]prioList, nCalls)
	ct.callToProgs = make([][]*Prog, nCalls)
	if len(corpus) == 0 {
		return
	}
	pairCounts := make(map[int]map[int]int)
	for _, p := range corpus {
		var ids []int
		for _, c := range p.Calls {
			if ct.Generatable(c.Meta.ID) {
				ids = append(ids, c.Meta.ID)
			}
		}
		if len(ids) < 2 {
			continue
		}
		for i, id0 := range ids {
			if slices.Contains(ids[:i], id0) {
				continue
			}
			ct.callToProgs[id0] = append(ct.callToProgs[id0], p)
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
			// Use sqrt() to lessen the effect of large counts.
			w := max(1, int32(2.0*math.Sqrt(float64(counts[id1]))))
			row.add(id1, w)
		}
		ct.dynamicCalls[id0] = row
	}
}

func (ct *ChoiceTable) Generatable(call int) bool {
	return call >= 0 && call < len(ct.generatable) && ct.generatable[call]
}

// RelatedPrograms returns focused plus unfocused programs from all that share a
// rare specific resource/type tag or syscall with focused.
func (ct *ChoiceTable) RelatedPrograms(focused, all []*Prog) []*Prog {
	if len(focused) == 0 || len(all) == 0 {
		return focused
	}
	focusedSet, focusTags, focusCalls := ct.collectFocusedFeatures(focused)
	tagProgs, callProgs := ct.countFeaturePrograms(all, focusTags, focusCalls)
	maxTagFreq := max(32, len(all)/25)
	maxCallFreq := max(16, len(all)/50)
	maxExtra := max(128, len(focused))
	res := slices.Clone(focused)
	extra := 0
	for _, p := range all {
		if focusedSet[p] ||
			!ct.matchesFocusedFeatures(p, focusTags, focusCalls, tagProgs, callProgs, maxTagFreq, maxCallFreq) {
			continue
		}
		res = append(res, p)
		if extra++; extra >= maxExtra {
			break
		}
	}
	return res
}

func (ct *ChoiceTable) collectFocusedFeatures(focused []*Prog) (map[*Prog]bool, []bool, []bool) {
	focusedSet := make(map[*Prog]bool, len(focused))
	focusTags := make([]bool, len(ct.tagCalls))
	focusCalls := make([]bool, len(ct.target.Syscalls))
	for _, p := range focused {
		focusedSet[p] = true
		for _, c := range p.Calls {
			id := c.Meta.ID
			if !ct.Generatable(id) {
				continue
			}
			for _, item := range ct.callTags[id] {
				if ct.specificTag[item.id] {
					focusCalls[id] = true
					if len(ct.tagCalls[item.id]) <= maxRelatedTagCalls {
						focusTags[item.id] = true
					}
				}
			}
		}
	}
	return focusedSet, focusTags, focusCalls
}

func (ct *ChoiceTable) countFeaturePrograms(all []*Prog, focusTags, focusCalls []bool) ([]int, []int) {
	tagProgs := make([]int, len(ct.tagCalls))
	callProgs := make([]int, len(ct.target.Syscalls))
	seenTag := make([]int, len(ct.tagCalls))
	seenCall := make([]int, len(ct.target.Syscalls))
	for idx, p := range all {
		stamp := idx + 1
		for _, c := range p.Calls {
			id := c.Meta.ID
			if id < 0 || id >= len(ct.target.Syscalls) {
				continue
			}
			if focusCalls[id] && seenCall[id] != stamp {
				seenCall[id] = stamp
				callProgs[id]++
			}
			for _, item := range ct.callTags[id] {
				if focusTags[item.id] && seenTag[item.id] != stamp {
					seenTag[item.id] = stamp
					tagProgs[item.id]++
				}
			}
		}
	}
	return tagProgs, callProgs
}

func (ct *ChoiceTable) matchesFocusedFeatures(p *Prog, focusTags, focusCalls []bool,
	tagProgs, callProgs []int, maxTagFreq, maxCallFreq int) bool {
	for _, c := range p.Calls {
		id := c.Meta.ID
		if !ct.Generatable(id) {
			continue
		}
		if focusCalls[id] && callProgs[id] <= maxCallFreq {
			return true
		}
		for _, item := range ct.callTags[id] {
			if focusTags[item.id] && tagProgs[item.id] <= maxTagFreq {
				return true
			}
		}
	}
	return false
}

// StaticPriorities returns the static two-hop transition probabilities from call
// to all syscalls in the target.
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

func (ct *ChoiceTable) chooseCalls(r *rand.Rand, calls []*Call) int {
	return ct.chooseWithContext(r, -1, calls)
}

func (ct *ChoiceTable) choose(r *rand.Rand, bias int) int {
	return ct.chooseWithContext(r, bias, nil)
}

func (ct *ChoiceTable) chooseWithContext(r *rand.Rand, bias int, contextCalls []*Call) int {
	if r.Intn(100) < 5 {
		// Let's make 5% decisions totally at random.
		return ct.calls[r.Intn(len(ct.calls))].ID
	}
	prefix := ct.uniquePrefix(contextCalls)
	if bias < 0 {
		if len(prefix) > 0 {
			// Pick primary bias from the prefix with a mild recency preference.
			idx := r.Intn(len(prefix))
			if r.Intn(2) == 0 {
				idx = max(idx, r.Intn(len(prefix)))
			}
			bias = prefix[idx]
		} else {
			bias = ct.calls[r.Intn(len(ct.calls))].ID
		}
	} else if !ct.Generatable(bias) {
		fmt.Printf("bias to disabled or non-generatable syscall %v\n", ct.target.Syscalls[bias].Name)
		panic("disabled or non-generatable syscall")
	}

	res := -1
	// Scale dynamic probability with the number of distinct co-occurring calls (up to 50%)
	// so a syscall that only appeared once in the corpus doesn't hand 50% of all future
	// choices to a single call.
	if dynProb := min(50, 15*len(ct.dynamicCalls[bias])); dynProb > 0 && r.Intn(100) < dynProb {
		res = ct.chooseDynamic(r, bias, prefix)
	}
	if res < 0 {
		res = ct.chooseStatic(r, bias, prefix)
	}
	if !ct.Generatable(res) {
		panic("selected disabled or non-generatable syscall")
	}
	return res
}

// uniquePrefix returns the unique generatable call IDs in calls, ordered by their most recent occurrence.
func (ct *ChoiceTable) uniquePrefix(calls []*Call) []int {
	var prefix []int
	for _, c := range slices.Backward(calls) {
		id := c.Meta.ID
		if ct.Generatable(id) && !slices.Contains(prefix, id) {
			prefix = append(prefix, id)
		}
	}
	slices.Reverse(prefix)
	return prefix
}

func (ct *ChoiceTable) chooseStaticSingle(r *rand.Rand, bias int) int {
	tags := ct.callTags[bias]
	if len(tags) == 0 {
		return ct.calls[r.Intn(len(ct.calls))].ID
	}
	// Two-hop walk on the bipartite static graph (call -> tag -> consumer call).
	// Reject self-loops (res == bias) 75% of the time so narrow 2-call tags don't
	// mostly pick the bias call itself.
	for range 4 {
		tagID := tags.sample(r)
		if res := ct.tagCalls[tagID].sample(r); res != bias || r.Intn(4) == 0 {
			return res
		}
	}
	return bias
}

func (ct *ChoiceTable) chooseStatic(r *rand.Rand, bias int, prefix []int) int {
	if len(prefix) <= 1 {
		return ct.chooseStaticSingle(r, bias)
	}
	// Sample 2 static candidates (one from the primary bias and one from an output-producing
	// or recent prefix call) and boost candidates that connect to >= 2 distinct prefix
	// calls via specific tags.
	var cands prioList
	for i := range 2 {
		b := bias
		if i > 0 {
			b = ct.sampleOutputSpecificPrefixCall(r, bias, prefix)
		}
		cand := ct.chooseStaticSingle(r, b)
		w := int32(10)
		matchedPrefix := 0
		bonusSum := int32(0)
		for _, pid := range prefix {
			if pid != cand {
				if minLen := ct.minSharedSpecificTagLen(pid, cand); minLen > 0 {
					matchedPrefix++
					bonusSum += max(1, int32(30/math.Sqrt(float64(minLen))))
				}
			}
		}
		if matchedPrefix >= 2 {
			w += bonusSum
		}
		cands.add(cand, w)
	}
	return cands.sample(r)
}

func (ct *ChoiceTable) sampleOutputSpecificPrefixCall(r *rand.Rand, bias int, prefix []int) int {
	var producers prioList
	for _, pid := range prefix {
		if pid == bias {
			continue
		}
		if minLen := ct.minOutTagLen[pid]; minLen > 0 {
			producers.add(pid, max(1, int32(100/math.Sqrt(float64(minLen)))))
		}
	}
	if len(producers) == 0 {
		return sampleRecent(r, prefix)
	}
	return producers.sample(r)
}

func (ct *ChoiceTable) minSharedSpecificTagLen(callA, callB int) int {
	// Since callTags slices are sorted by tagID, find the smallest shared specific tag in a linear merge scan.
	tagsA, tagsB := ct.callTags[callA], ct.callTags[callB]
	minLen := 0
	for i, j := 0, 0; i < len(tagsA) && j < len(tagsB); {
		idA, idB := tagsA[i].id, tagsB[j].id
		if idA == idB {
			if ct.specificTag[idA] {
				if n := len(ct.tagCalls[idA]); minLen == 0 || n < minLen {
					minLen = n
				}
			}
			i++
			j++
		} else if idA < idB {
			i++
		} else {
			j++
		}
	}
	return minLen
}

func (ct *ChoiceTable) chooseDynamic(r *rand.Rand, bias int, prefix []int) int {
	row := ct.dynamicCalls[bias]
	if len(row) == 0 {
		return -1
	}
	if len(prefix) <= 1 || len(row) == 1 {
		return row.sample(r)
	}

	var cands prioList

	// Part 1: Check up to 4 corpus programs for the rarest, most recent, and biased prefix calls.
	// If a sampled program shares >= 2 calls with our prefix, pick a call that follows them.
	for _, seedPID := range ct.dynamicSeeds(bias, prefix) {
		progs := ct.callToProgs[seedPID]
		for range min(4, len(progs)) {
			p := progs[r.Intn(len(progs))]
			if cand, score := ct.sampleProgFollowup(r, p, prefix); score > 0 {
				cands.add(cand, score)
			}
		}
	}

	// Part 2: Sample 5 candidate syscalls using pairwise dynamicCalls tables (2 from bias and
	// 3 from other calls in the prefix), and boost candidates that commonly follow multiple
	// calls in our prefix (weighting more recent prefix calls 1x..3x higher).
	for i := range 5 {
		srcCall := bias
		if i >= 2 {
			if other := sampleRecent(r, prefix); len(ct.dynamicCalls[other]) > 0 {
				srcCall = other
			}
		}
		cand := ct.dynamicCalls[srcCall].sample(r)
		w := int32(10)
		for idx, pid := range prefix {
			if rw := ct.dynamicCalls[pid].relWeight(cand); rw > 0 {
				recency := int32(1 + idx*2/len(prefix))
				w += recency * (3 + min(20, rw/10))
			}
		}
		cands.add(cand, w)
	}
	return cands.sample(r)
}

func (ct *ChoiceTable) dynamicSeeds(bias int, prefix []int) []int {
	rarest := bias
	for _, pid := range prefix {
		if n := len(ct.callToProgs[pid]); n > 0 &&
			(len(ct.callToProgs[rarest]) == 0 || n < len(ct.callToProgs[rarest])) {
			rarest = pid
		}
	}
	var seeds []int
	for _, pid := range [3]int{rarest, prefix[len(prefix)-1], bias} {
		if !slices.Contains(seeds, pid) {
			seeds = append(seeds, pid)
		}
	}
	return seeds
}

func (ct *ChoiceTable) sampleProgFollowup(r *rand.Rand, p *Prog, prefix []int) (int, int32) {
	matched, firstPos, lastPos := 0, -1, -1
	for pos, c := range p.Calls {
		if slices.Contains(prefix, c.Meta.ID) {
			matched++
			if firstPos < 0 {
				firstPos = pos
			}
			lastPos = pos
		}
	}
	if matched < 2 || firstPos+1 >= len(p.Calls) {
		return 0, 0
	}
	startPos := lastPos + 1
	if startPos >= len(p.Calls) {
		startPos = firstPos + 1
	}
	cand := p.Calls[startPos+r.Intn(len(p.Calls)-startPos)].Meta.ID
	if !ct.Generatable(cand) {
		return 0, 0
	}
	// Prefer specialized syscalls (small df = len(callToProgs[cand])) over generic
	// syscalls like close/mmap that appear in thousands of corpus programs.
	df := max(1, len(ct.callToProgs[cand]))
	score := int32(matched) * max(2, int32(40.0/math.Sqrt(float64(df))))
	if startPos > lastPos {
		score *= 2
	}
	return cand, score
}

func sampleRecent(r *rand.Rand, prefix []int) int {
	return prefix[max(r.Intn(len(prefix)), r.Intn(len(prefix)))]
}
