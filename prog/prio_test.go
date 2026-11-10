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

// Static selection must favor consumers of the specific resource subtype produced by the bias
// call (test$consume_subtype_of_common) over consumers of its parent resource (test$consume_common).
func TestStaticResourceSpecificity(t *testing.T) {
	target := initTargetTest(t, "test", "64")
	ct := target.DefaultChoiceTable()
	prios := ct.StaticPriorities(target.SyscallMap["test$produce_subtype_of_common"])
	specific := prios[target.SyscallMap["test$consume_subtype_of_common"].ID]
	generic := prios[target.SyscallMap["test$consume_common"].ID]
	assert.Greater(t, specific, generic*3)
}

// Static selection must boost calls that share specific resources with several calls in the prefix:
// test$r103_producer_r104_consumer shares resources with 2 prefix calls, while test$consume_common
// only shares common with test$produce_common.
func TestStaticMultiPrefixBoost(t *testing.T) {
	target := initTargetTest(t, "test", "64")
	shares := chooseShares(t, target.DefaultChoiceTable(), `test$produce_common()
test$r103_consumer(0x0)
test$r104_producer(0x0)
`)
	assert.Greater(t, shares["test$r103_producer_r104_consumer"], shares["test$consume_common"]*2)
}

// Dynamic selection must prefer calls that followed the bias call in the corpus,
// but neither let them monopolize the choices, nor let a call that was seen with
// a single other call hand half of all choices to that call.
func TestDynamicPriorities(t *testing.T) {
	target := initTargetTest(t, "test", "64")
	ct := buildTestChoiceTable(t, target, []testCorpusProg{
		{80, "test$res0()\ntest$int(0x1, 0x2, 0x3, 0x4, 0x5)\n"},
		{20, "test$res0()\ntest$opt1(0x0)\ntest$align0(0x0)\n"},
		{1, "test$align1(0x0)\ntest$align2(0x0)\n"},
	})
	// test$res0 is followed by 3 distinct calls in the corpus, so the dynamic table is
	// used with the maxDynamicPercent (50%) probability, and test$int has the largest
	// weight (sqrt(80) vs sqrt(20)) in it.
	shares := chooseShares(t, ct, "test$res0()\n")
	assert.Greater(t, shares["test$int"], 0.05)
	assert.Less(t, shares["test$int"], 0.4)

	// test$align1 is followed by a single call, so the dynamic table is used only with the
	// dynamicPercentPerCall (15%) probability.
	shares = chooseShares(t, ct, "test$align1(0x0)\n")
	assert.Greater(t, shares["test$align2"], 0.02)
	assert.Less(t, shares["test$align2"], 0.2)

	// test$align0 follows both calls of the prefix in the corpus, so it must be boosted.
	shares = chooseShares(t, ct, "test$res0()\ntest$opt1(0x0)\n")
	assert.Greater(t, shares["test$align0"], 0.05)
}

// Given a multi-call prefix, dynamic selection must find the corpus programs that contain
// the prefix and prefer the specialized calls that follow it there (test$r101_producer_recur)
// over ubiquitous calls that appear in most corpus programs (mutate0).
func TestDynamicSpecializedFollowup(t *testing.T) {
	target := initTargetTest(t, "test", "64")
	ct := buildTestChoiceTable(t, target, []testCorpusProg{
		{5, "test$r100_producer(0x0)\ntest$r100_consumer(0x0)\ntest$r101_producer_recur(0x0)\nmutate0()\n"},
		{50, "mutate1()\nmutate0()\n"},
	})
	shares := chooseShares(t, ct, "test$r100_producer(0x0)\ntest$r100_consumer(0x0)\n")
	assert.Greater(t, shares["test$r101_producer_recur"], shares["mutate0"]*1.5)
}

func TestFollowupWeight(t *testing.T) {
	tests := []struct {
		df, n int
		want  int32
	}{
		// Small focused corpora: n is floored at minEffectiveCorpus, so a call that
		// appears in a single program gets the maximum weight (4*sqrt(100/1) = 40),
		// and a call that appears in all programs gets 4*sqrt(100/50) = 5.
		{df: 1, n: 50, want: 40},
		{df: 50, n: 50, want: 5},
		// Large continuous corpora: a subsystem call (5% of programs) keeps a >3x higher
		// weight (4*sqrt(10000/500) = 17) than a ubiquitous call (85% of programs,
		// 4*sqrt(10000/8500) = 4), instead of both collapsing to the floor.
		{df: 500, n: 10000, want: 17},
		{df: 8500, n: 10000, want: 4},
		// The weight never drops below the floor.
		{df: 10000, n: 10000, want: 4},
		{df: 1000000, n: 10000, want: 2},
	}
	for _, test := range tests {
		assert.Equal(t, test.want, followupWeight(test.df, test.n), "df=%v n=%v", test.df, test.n)
	}
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
	// Compare everything except for the target pointer.
	tables := func(ct *ChoiceTable) ChoiceTable {
		ret := *ct
		ret.target = nil
		return ret
	}
	require.Equal(t, tables(ct0), tables(ct1))
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

// testCorpusProg is a program that is repeated count times in a test corpus.
type testCorpusProg struct {
	count int
	prog  string
}

func buildTestChoiceTable(t *testing.T, target *Target, corpus []testCorpusProg) *ChoiceTable {
	var progs []*Prog
	for _, cp := range corpus {
		p, err := target.Deserialize([]byte(cp.prog), Strict)
		require.NoError(t, err)
		for range cp.count {
			progs = append(progs, p)
		}
	}
	return target.BuildChoiceTable(progs, nil)
}

// chooseShares returns the share of the next call choices for the given program prefix
// that each syscall gets.
func chooseShares(t *testing.T, ct *ChoiceTable, prefix string) map[string]float64 {
	p, err := ct.target.Deserialize([]byte(prefix), Strict)
	require.NoError(t, err)
	const iters = 10000
	r := rand.New(rand.NewSource(0))
	shares := make(map[string]float64)
	for range iters {
		shares[ct.target.Syscalls[ct.chooseCalls(r, p.Calls)].Name] += 1.0 / iters
	}
	return shares
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
