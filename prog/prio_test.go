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
	shares := chooseShares(ct, "test$res0")
	assert.Greater(t, shares["test$int"], 0.05)
	assert.Less(t, shares["test$int"], 0.4)

	// test$align1 is followed by a single call, so the dynamic table is used only with the
	// dynamicPercentPerCall (15%) probability.
	shares = chooseShares(ct, "test$align1")
	assert.Greater(t, shares["test$align2"], 0.02)
	assert.Less(t, shares["test$align2"], 0.2)
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

// chooseShares returns the share of the next call choices after the bias call that each syscall gets.
func chooseShares(ct *ChoiceTable, bias string) map[string]float64 {
	const iters = 10000
	r := rand.New(rand.NewSource(0))
	shares := make(map[string]float64)
	for range iters {
		shares[ct.target.Syscalls[ct.choose(r, ct.target.SyscallMap[bias].ID)].Name] += 1.0 / iters
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
