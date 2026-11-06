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
//     weighted by sqrt(number of such programs).
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
	// Maximum tag size considered specific when boosting multi-prefix resource consumers.
	maxSpecificTagCalls = 600
	// Base weight of a candidate sampled for a multi-call prefix (see chooseStatic and
	// chooseDynamic) before any bonuses for matching several prefix calls.
	baseCandWeight = 10
	// A candidate gets the multi-prefix bonuses only if it's connected
	// to at least that many distinct prefix calls.
	minMatchedPrefixCalls = 2
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

// relWeight returns id's share of the list's total weight in per-mille (1..1000), or 0 if absent.
// The list must be sorted by id.
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
	dynamicCalls      []prioList
	callToProgs       [][]*Prog
	numMultiCallProgs int
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
			consumers.add(w.call, w.in*tagDirWeight+w.inout)
		}
		ct.tagCalls = append(ct.tagCalls, consumers)
		ct.specificTag = append(ct.specificTag,
			tag != tagFilename && tag != tagVma && len(consumers) <= maxSpecificTagCalls)

		// Weight the tag by (tagDirWeight*out + in) * sqrt(min(tagSum, maxStaticTagSumScale)) so
		// resources produced by the bias call are preferred over resources it only consumes,
		// without letting huge generic tags (like fd) drown out specific subkinds.
		tagScale := max(1, int32(math.Sqrt(float64(min(consumers.total(), maxStaticTagSumScale)))))
		for _, w := range callWeights {
			ct.callTags[w.call].add(tagID, (w.out*tagDirWeight+w.in)*tagScale)
			if w.out > 0 && (ct.minOutTagLen[w.call] == 0 || len(consumers) < ct.minOutTagLen[w.call]) {
				ct.minOutTagLen[w.call] = len(consumers)
			}
		}
	}
}

func (ct *ChoiceTable) buildDynamicPriorities(corpus []*Prog) {
	ct.dynamicCalls = make([]prioList, len(ct.target.Syscalls))
	ct.callToProgs = make([][]*Prog, len(ct.target.Syscalls))
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
		ct.numMultiCallProgs++
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

// chooseCalls chooses the next call for the program prefix calls.
func (ct *ChoiceTable) chooseCalls(r *rand.Rand, calls []*Call) int {
	return ct.chooseWithContext(r, -1, calls)
}

// choose chooses the next call after the bias call (or a random one if bias < 0).
func (ct *ChoiceTable) choose(r *rand.Rand, bias int) int {
	return ct.chooseWithContext(r, bias, nil)
}

func (ct *ChoiceTable) chooseWithContext(r *rand.Rand, bias int, contextCalls []*Call) int {
	if r.Intn(100) < 5 {
		// Let's make 5% decisions totally at random.
		return ct.randomCall(r)
	}
	prefix := ct.uniquePrefix(contextCalls)
	if bias < 0 {
		if len(prefix) > 0 {
			// Pick the primary bias from the prefix with a mild recency preference
			// (uniform in half of the cases, the same as sampleRecent otherwise).
			idx := r.Intn(len(prefix))
			if r.Intn(2) == 0 {
				idx = max(idx, r.Intn(len(prefix)))
			}
			bias = prefix[idx]
		} else {
			bias = ct.randomCall(r)
		}
	} else if !ct.Generatable(bias) {
		fmt.Printf("bias to disabled or non-generatable syscall %v\n", ct.target.Syscalls[bias].Name)
		panic("disabled or non-generatable syscall")
	}
	var res int
	row := ct.dynamicCalls[bias]
	if dynProb := min(maxDynamicPercent, dynamicPercentPerCall*len(row)); r.Intn(100) < dynProb {
		res = ct.chooseDynamic(r, bias, prefix)
	} else {
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

// sampleRecent samples a prefix call with a preference for more recent ones
// (the probability grows linearly with the position in the prefix).
func sampleRecent(r *rand.Rand, prefix []int) int {
	return prefix[max(r.Intn(len(prefix)), r.Intn(len(prefix)))]
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

const (
	// Number of candidates sampled by chooseStatic for a multi-call prefix.
	staticCands = 2
	// Bonus of a static candidate for each prefix call it shares a specific tag with
	// is staticMatchBonusScale/sqrt(number of consumers of the most specific shared tag).
	staticMatchBonusScale = 30
)

// chooseStatic chooses the next call based on the static priorities of the bias call
// and other calls in the prefix.
func (ct *ChoiceTable) chooseStatic(r *rand.Rand, bias int, prefix []int) int {
	if len(prefix) <= 1 {
		return ct.chooseStaticSingle(r, bias)
	}
	// Sample staticCands candidates (one from the primary bias and the rest from
	// output-producing or recent prefix calls) and boost candidates that connect to
	// several distinct prefix calls via specific tags.
	var cands prioList
	for i := range staticCands {
		b := bias
		if i > 0 {
			b = ct.sampleProducerPrefixCall(r, bias, prefix)
		}
		cand := ct.chooseStaticSingle(r, b)
		w := int32(baseCandWeight)
		matchedPrefix := 0
		bonusSum := int32(0)
		for _, pid := range prefix {
			if pid != cand {
				if minLen := ct.minSharedSpecificTagLen(pid, cand); minLen > 0 {
					matchedPrefix++
					bonusSum += max(1, int32(staticMatchBonusScale/math.Sqrt(float64(minLen))))
				}
			}
		}
		if matchedPrefix >= minMatchedPrefixCalls {
			w += bonusSum
		}
		cands.add(cand, w)
	}
	return cands.sample(r)
}

// Weight of a prefix call in sampleProducerPrefixCall is
// producerWeightScale/sqrt(number of consumers of its most specific output tag).
const producerWeightScale = 100

// sampleProducerPrefixCall samples a prefix call other than bias that produces a resource/type,
// preferring producers of more specific ones. If there are none, it samples a recent prefix call.
func (ct *ChoiceTable) sampleProducerPrefixCall(r *rand.Rand, bias int, prefix []int) int {
	var producers prioList
	for _, pid := range prefix {
		if pid == bias {
			continue
		}
		if minLen := ct.minOutTagLen[pid]; minLen > 0 {
			producers.add(pid, max(1, int32(producerWeightScale/math.Sqrt(float64(minLen)))))
		}
	}
	if len(producers) == 0 {
		return sampleRecent(r, prefix)
	}
	return producers.sample(r)
}

// minSharedSpecificTagLen returns the number of consumers of the most specific tag
// shared by callA and callB, or 0 if they don't share specific tags.
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

const (
	// Number of corpus programs inspected per seed call (see dynamicSeeds).
	followupProgsPerSeed = 4
	// Number of candidates sampled from dynamicCalls for a multi-call prefix,
	// dynamicBiasCands of them from the bias call and the rest from other prefix calls.
	dynamicCands     = 5
	dynamicBiasCands = 2
	// Bonus of a dynamic candidate for each prefix call it followed in the corpus is
	// recency * (dynamicMatchBonus + min(maxDynamicRelBonus, relWeight/dynamicRelBonusDiv)),
	// where relWeight is the candidate's per-mille share in the prefix call's dynamicCalls,
	// and recency grows from 1 for the oldest prefix call to maxRecencyWeight for the newest.
	dynamicMatchBonus  = 3
	maxDynamicRelBonus = 20
	dynamicRelBonusDiv = 10
	maxRecencyWeight   = 3
)

// chooseDynamic chooses the next call based on the corpus programs that contain the bias call
// and other calls in the prefix.
func (ct *ChoiceTable) chooseDynamic(r *rand.Rand, bias int, prefix []int) int {
	row := ct.dynamicCalls[bias]
	if len(prefix) <= 1 || len(row) == 1 {
		return row.sample(r)
	}

	var cands prioList

	// Part 1: Check a few corpus programs for the rarest, most recent, and bias prefix calls.
	// If a sampled program shares several calls with our prefix, pick a call that follows them.
	for _, seedPID := range ct.dynamicSeeds(bias, prefix) {
		progs := ct.callToProgs[seedPID]
		for range min(followupProgsPerSeed, len(progs)) {
			p := progs[r.Intn(len(progs))]
			if cand, score := ct.sampleProgFollowup(r, p, prefix); score > 0 {
				cands.add(cand, score)
			}
		}
	}

	// Part 2: Sample candidate syscalls using pairwise dynamicCalls tables (from bias and
	// from other calls in the prefix), and boost candidates that commonly follow multiple
	// calls in our prefix (weighting more recent prefix calls higher).
	for i := range dynamicCands {
		srcCall := bias
		if i >= dynamicBiasCands {
			if other := sampleRecent(r, prefix); len(ct.dynamicCalls[other]) > 0 {
				srcCall = other
			}
		}
		cand := ct.dynamicCalls[srcCall].sample(r)
		w := int32(baseCandWeight)
		for idx, pid := range prefix {
			if rw := ct.dynamicCalls[pid].relWeight(cand); rw > 0 {
				recency := int32(1 + idx*(maxRecencyWeight-1)/len(prefix))
				w += recency * (dynamicMatchBonus + min(maxDynamicRelBonus, rw/dynamicRelBonusDiv))
			}
		}
		cands.add(cand, w)
	}
	return cands.sample(r)
}

// dynamicSeeds returns the prefix calls whose corpus programs are inspected for followups:
// the rarest one (its programs are the most likely to be specific to our prefix),
// the most recent one (recency), and the bias call (consistency with the single-call choice).
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

// Followups that come after all matched prefix calls in the corpus program
// score inOrderFollowupBonus times higher.
const inOrderFollowupBonus = 2

// sampleProgFollowup samples a call that follows the prefix calls in the corpus program p
// and returns it with its score, or 0 score if p doesn't share enough calls with the prefix.
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
	if matched < minMatchedPrefixCalls {
		return 0, 0
	}
	// If nothing follows the last matched call, sample after the first one instead
	// (firstPos < lastPos since matched >= 2, so there's always something after it).
	startPos := lastPos + 1
	inOrder := startPos < len(p.Calls)
	if !inOrder {
		startPos = firstPos + 1
	}
	cand := p.Calls[startPos+r.Intn(len(p.Calls)-startPos)].Meta.ID
	if !ct.Generatable(cand) {
		return 0, 0
	}
	score := int32(matched) * followupWeight(len(ct.callToProgs[cand]), ct.numMultiCallProgs)
	if inOrder {
		score *= inOrderFollowupBonus
	}
	return cand, score
}

const (
	// Followup weight is followupWeightScale*sqrt(N/df), clamped to
	// [minFollowupWeight, maxFollowupWeight], where N is the number of multi-call corpus
	// programs floored at minEffectiveCorpus.
	followupWeightScale = 4.0
	minFollowupWeight   = 2
	maxFollowupWeight   = 40
	minEffectiveCorpus  = 100
)

// followupWeight returns the weight of a followup candidate that appears in df out of n
// multi-call corpus programs. Specialized syscalls (small df/n) are preferred over generic
// syscalls like close/mmap that appear in most programs. Flooring n at minEffectiveCorpus
// keeps the weights of small focused corpora in the (minFollowupWeight, maxFollowupWeight)
// range, while large continuous corpora keep scale-invariant weights.
func followupWeight(df, n int) int32 {
	df = max(1, df)
	n = max(minEffectiveCorpus, n)
	w := int32(followupWeightScale * math.Sqrt(float64(n)/float64(df)))
	return min(maxFollowupWeight, max(minFollowupWeight, w))
}
