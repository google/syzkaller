// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"math/rand"
	"testing"

	"github.com/google/syzkaller/pkg/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Test static priorities assigned based on argument direction.
func TestStaticPriorities(t *testing.T) {
	target := initTargetTest(t, "linux", "amd64")
	rs := rand.NewSource(0)
	// The test is probabilistic and needs some sensible number of iterations to succeed.
	// If it fails try to increase the number a bit.
	const iters = 200000
	// The first call is the one that creates a resource and the rest are calls that can use that resource.
	tests := [][]string{
		{"open", "read", "write", "mmap"},
		{"socket", "listen", "setsockopt"},
	}
	ct := target.DefaultChoiceTable()
	r := rand.New(rs)
	for _, syscalls := range tests {
		// Counts the number of times a call is chosen after a call that creates a resource (referenceCall).
		counter := make(map[string]int)
		referenceCall := syscalls[0]
		refMeta := target.SyscallMap[referenceCall]
		staticPrios := ct.StaticPriorities(refMeta)
		for _, call := range syscalls {
			count := 0
			for range iters {
				chosenCall := target.Syscalls[ct.choose(r, target.SyscallMap[call].ID)].Name
				if call == referenceCall {
					counter[chosenCall]++
				} else if chosenCall == referenceCall {
					count++
				}
			}
			if call == referenceCall {
				continue
			}
			// Checks that prio[callCreatesRes][callUsesRes] > prio[callUsesRes][callCreatesRes]
			require.Lessf(t, count, counter[call], "too high priority for %s -> %s: %d vs %s -> %s: %d",
				call, referenceCall, count, referenceCall, call, counter[call])
			callMeta := target.SyscallMap[call]
			revPrios := ct.StaticPriorities(callMeta)
			assert.Greater(t, staticPrios[callMeta.ID], revPrios[refMeta.ID],
				"static priority %s -> %s should exceed %s -> %s",
				referenceCall, call, call, referenceCall)
		}
	}
}

// Verify that static selection favors specific resource subtypes over parent resources
// (e.g. test$consume_subtype_of_common after test$produce_subtype_of_common rather than
// test$consume_common), and boosts calls that consume multiple resources from the prefix
// (e.g. test$r103_producer_r104_consumer when the prefix uses both r103 and r104).
func TestStaticResourceSpecificityAndMultiPrefix(t *testing.T) {
	target := initTargetTest(t, "test", "64")
	ct := target.DefaultChoiceTable()

	prodSub := target.SyscallMap["test$produce_subtype_of_common"]
	consSub := target.SyscallMap["test$consume_subtype_of_common"]
	consCommon := target.SyscallMap["test$consume_common"]
	require.NotNil(t, prodSub)
	require.NotNil(t, consSub)
	require.NotNil(t, consCommon)

	// test$produce_subtype_of_common produces subtype_of_common (a subtype of common).
	// StaticPriorities should give higher weight to test$consume_subtype_of_common than
	// to a generic parent-resource consumer like test$consume_common.
	subPrios := ct.StaticPriorities(prodSub)
	assert.Greater(t, subPrios[consSub.ID], subPrios[consCommon.ID]*3,
		"specific subtype consumer should have much higher priority than generic parent consumer")

	// Multi-call static boost: test$optional_res consumes optional_res1, optional_res2,
	// required_res1, and required_res2, while test$output_res produces all four and
	// test$produce_common only uses common. When the prefix contains [test$produce_common, test$output_res],
	// a candidate that shares multiple tags or connects to multiple prefix calls is boosted:
	// compare test$r103_producer_r104_consumer (which uses both r103 and r104) against
	// test$consume_common (which only uses common) when the prefix is
	// [test$produce_common, test$r103_consumer, test$r104_producer].
	prefixProg, err := target.Deserialize([]byte(`test$produce_common()
test$r103_consumer(0x0)
test$r104_producer(0x0)
`), Strict)
	require.NoError(t, err)
	bothID := target.SyscallMap["test$r103_producer_r104_consumer"].ID

	const iters = 20000
	r := rand.New(rand.NewSource(1))
	counts := make(map[int]int)
	for range iters {
		counts[ct.chooseCalls(r, prefixProg.Calls)]++
	}
	assert.Greater(t, counts[bothID], counts[consCommon.ID]*2,
		"call sharing specific tags with two prefix calls (%d) should beat one (%d)",
		counts[bothID], counts[consCommon.ID])

	// Verify sampleOutputSpecificPrefixCall only considers calls that produce outputs
	// and samples among multiple output-producing prefix calls probabilistically.
	r103ConsID := target.SyscallMap["test$r103_consumer"].ID
	r104ProdID := target.SyscallMap["test$r104_producer"].ID
	assert.Zero(t, ct.minOutTagLen[r103ConsID], "input-only consumer should have minOutTagLen == 0")
	assert.Positive(t, ct.minOutTagLen[prodSub.ID], "output producer should have minOutTagLen > 0")
	assert.Positive(t, ct.minOutTagLen[r104ProdID], "output producer should have minOutTagLen > 0")

	prefixIDs := []int{r103ConsID, prodSub.ID, r104ProdID}
	sampledProducers := make(map[int]int)
	for range 1000 {
		sampledProducers[ct.sampleOutputSpecificPrefixCall(r, -1, prefixIDs)]++
	}
	assert.Zero(t, sampledProducers[r103ConsID], "input-only call must not be sampled as output producer")
	assert.Positive(t, sampledProducers[prodSub.ID], "first output producer should be sampled")
	assert.Positive(t, sampledProducers[r104ProdID], "second output producer should be sampled")
}

// Verify that given a multi-call prefix (e.g. test$r100_producer -> test$r100_consumer),
// chooseDynamic matches corpus programs containing that prefix and prefers specialized
// follow-up calls (like test$r101_producer_recur) over ubiquitous calls (like mutate0)
// that appear in many unrelated corpus programs.
func TestDynamicMultiCallWorkflow(t *testing.T) {
	target := initTargetTest(t, "test", "64")
	workflow, err := target.Deserialize([]byte(`test$r100_producer(0x0)
test$r100_consumer(0x0)
test$r101_producer_recur(0x0)
mutate0()
`), Strict)
	require.NoError(t, err)

	// Populate the corpus with 50 unrelated programs that all end with mutate0(),
	// so mutate0() has high document frequency while test$r101_producer_recur is specific.
	unrelated, err := target.Deserialize([]byte(`mutate1()
mutate0()
`), Strict)
	require.NoError(t, err)

	var corpus []*Prog
	for range 5 {
		corpus = append(corpus, workflow.Clone())
	}
	for range 50 {
		corpus = append(corpus, unrelated.Clone())
	}
	ct := target.BuildChoiceTable(corpus, nil)

	prefixProg, err := target.Deserialize([]byte(`test$r100_producer(0x0)
test$r100_consumer(0x0)
`), Strict)
	require.NoError(t, err)

	specializedID := target.SyscallMap["test$r101_producer_recur"].ID
	ubiquitousID := target.SyscallMap["mutate0"].ID

	r := rand.New(rand.NewSource(0))
	const iters = 20000
	counts := make(map[int]int)
	for range iters {
		counts[ct.chooseCalls(r, prefixProg.Calls)]++
	}
	assert.Greater(t, counts[specializedID], counts[ubiquitousID]*3/2,
		"specialized workflow follow-up (%d) should be preferred over ubiquitous mutate0 (%d)",
		counts[specializedID], counts[ubiquitousID])
}

func TestDynamicPriorities(t *testing.T) {
	target := initTargetTest(t, "test", "64")
	pColocated, err := target.Deserialize([]byte("test$res0()\ntest$int(0x1, 0x2, 0x3, 0x4, 0x5)\n"), Strict)
	require.NoError(t, err)
	pMulti, err := target.Deserialize([]byte("test$res0()\ntest$opt1(0x0)\ntest$align0(0x0)\n"), Strict)
	require.NoError(t, err)
	pSinglePair, err := target.Deserialize([]byte("test$align1(0x0)\ntest$align2(0x0)\n"), Strict)
	require.NoError(t, err)

	var corpus []*Prog
	for range 80 {
		corpus = append(corpus, pColocated.Clone())
	}
	for range 20 {
		corpus = append(corpus, pMulti.Clone())
	}
	corpus = append(corpus, pSinglePair)

	ct := target.BuildChoiceTable(corpus, nil)
	res0ID := target.SyscallMap["test$res0"].ID
	intID := target.SyscallMap["test$int"].ID
	align0ID := target.SyscallMap["test$align0"].ID
	align1ID := target.SyscallMap["test$align1"].ID
	align2ID := target.SyscallMap["test$align2"].ID

	// Verify that dynamic colocation boosts test$int after test$res0 while still exploring static/other calls.
	r := rand.New(rand.NewSource(0))
	const iters = 10000
	counts := make(map[int]int)
	for range iters {
		counts[ct.choose(r, res0ID)]++
	}
	assert.Greater(t, counts[intID], iters/20, "colocated call should be chosen frequently")
	assert.Less(t, counts[intID], iters*4/10, "colocated call should not monopolize all choices")

	// Verify that a call with only a single known co-occurring call in the corpus
	// does not hand 50% of all choices to that single pair.
	singleCounts := make(map[int]int)
	for range iters {
		singleCounts[ct.choose(r, align1ID)]++
	}
	assert.Greater(t, singleCounts[align2ID], iters/50, "single corpus pair should still be explored")
	assert.Less(t, singleCounts[align2ID], iters/5, "single corpus pair must not hog 50%% of choices")

	// Verify multi-call context: when prefix is [test$res0, test$opt1], test$align0 is colocated with both.
	prefixProg, err := target.Deserialize([]byte("test$res0()\ntest$opt1(0x0)\n"), Strict)
	require.NoError(t, err)
	multiCounts := make(map[int]int)
	for range iters {
		multiCounts[ct.chooseCalls(r, prefixProg.Calls)]++
	}
	assert.Greater(t, multiCounts[align0ID], iters/20, "multi-call colocated call should be boosted")
}

func TestRelatedPrograms(t *testing.T) {
	target := initTargetTest(t, "test", "64")
	pFocused, err := target.Deserialize([]byte("r0 = mutate5(&(0x7f0000000000)='./file0\\x00', 0x3)\n"), Strict)
	require.NoError(t, err)
	pRelatedConsumer, err := target.Deserialize(
		[]byte("mutate6(0xffffffffffffffff, &(0x7f0000000000)=\"00\", 0x1)\n"), Strict)
	require.NoError(t, err)
	pUnrelated, err := target.Deserialize([]byte("test$int(0x1, 0x2, 0x3, 0x4, 0x5)\n"), Strict)
	require.NoError(t, err)

	all := []*Prog{pFocused, pRelatedConsumer}
	for range 50 {
		all = append(all, pUnrelated.Clone())
	}
	ct := target.DefaultChoiceTable()
	got := ct.RelatedPrograms([]*Prog{pFocused}, all)
	assert.Contains(t, got, pFocused)
	assert.Contains(t, got, pRelatedConsumer, "unfocused consumer of specific resource should be retained")
	assert.Len(t, got, 2, "unrelated programs must not be pulled in")
}

func TestPrioDeterminism(t *testing.T) {
	if testutil.RaceEnabled {
		t.Skip("skipping in race mode, too slow")
	}
	target, rs, iters := initTest(t)
	ct := target.DefaultChoiceTable()
	var corpus []*Prog
	for range 100 {
		corpus = append(corpus, target.Generate(rs, 10, ct))
	}
	ct0 := target.BuildChoiceTable(corpus, nil)
	ct1 := target.BuildChoiceTable(corpus, nil)
	require.Equal(t, ct0.callTags, ct1.callTags)
	require.Equal(t, ct0.tagCalls, ct1.tagCalls)
	require.Equal(t, ct0.minOutTagLen, ct1.minOutTagLen)
	require.Equal(t, ct0.specificTag, ct1.specificTag)
	require.Equal(t, ct0.dynamicCalls, ct1.dynamicCalls)
	require.Equal(t, ct0.callToProgs, ct1.callToProgs)
	for i := range iters {
		seed := rs.Int63()
		call0 := ct0.choose(rand.New(rand.NewSource(seed)), -1)
		call1 := ct1.choose(rand.New(rand.NewSource(seed)), -1)
		require.Equal(t, call0, call1, "seed=%v iter=%v", seed, i)

		p := corpus[i%len(corpus)]
		callCtx0 := ct0.chooseCalls(rand.New(rand.NewSource(seed)), p.Calls)
		callCtx1 := ct1.chooseCalls(rand.New(rand.NewSource(seed)), p.Calls)
		require.Equal(t, callCtx0, callCtx1, "seed=%v iter=%v", seed, i)
	}
}

func BenchmarkBuildChoiceTable(b *testing.B) {
	target, cleanup := initBench(b)
	defer cleanup()
	for range b.N {
		target.BuildChoiceTable(nil, nil)
	}
}

func BenchmarkChoiceTableChoose(b *testing.B) {
	target, cleanup := initBench(b)
	defer cleanup()
	rs := rand.NewSource(0)
	ct0 := target.DefaultChoiceTable()
	var corpus []*Prog
	for range 1000 {
		corpus = append(corpus, target.Generate(rs, 20, ct0))
	}
	ct := target.BuildChoiceTable(corpus, nil)
	r := rand.New(rs)
	sampleProg := corpus[0]
	b.ResetTimer()
	for i := range b.N {
		ct.chooseCalls(r, sampleProg.Calls[:i%len(sampleProg.Calls)+1])
	}
}
