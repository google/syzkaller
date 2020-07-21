// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"math/rand"
	"reflect"
	"testing"
)

func TestNormalizePrio(t *testing.T) {
	prios := [][]float32{
		{2, 2, 2},
		{1, 2, 4},
		{1, 2, 0},
	}
	want := [][]float32{
		{1, 1, 1},
		{0.1, 0.4, 1},
		{0.4, 1, 0.1},
	}
	t.Logf("had:  %+v", prios)
	normalizePrio(prios)
	if !reflect.DeepEqual(prios, want) {
		t.Logf("got:  %+v", prios)
		t.Errorf("want: %+v", want)
	}
}

// Test static priorities assigned based on argument direction.
func TestStaticPriorities(t *testing.T) {
	target := initTargetTest(t, "linux", "amd64")
	rs := rand.NewSource(0)
	// The test is probabilistic and needs some sensible number of iterations to succeed.
	// If it fails try to increase the number a bit.
	const iters = 2e5
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
		for _, call := range syscalls {
			count := 0
			for it := 0; it < iters; it++ {
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
			if count >= counter[call] {
				t.Fatalf("Too high priority for %s -> %s: %d vs %s -> %s: %d",
					call, referenceCall, count, referenceCall, call, counter[call])
			}
		}
	}
}

func TestPrioDeterminism(t *testing.T) {
	if raceEnabled {
		t.Skip("skipping in race mode, too slow")
	}
	target, rs, iters := initTest(t)
	ct := target.DefaultChoiceTable()
	var corpus []*Prog
	for i := 0; i < 100; i++ {
		corpus = append(corpus, target.Generate(rs, 10, ct))
	}
	ct0 := target.BuildChoiceTable(corpus, nil)
	ct1 := target.BuildChoiceTable(corpus, nil)
	if !reflect.DeepEqual(ct0.runs, ct1.runs) {
		t.Fatal("non-deterministic ChoiceTable")
	}
	for i := 0; i < iters; i++ {
		seed := rs.Int63()
		call0 := ct0.choose(rand.New(rand.NewSource(seed)), -1)
		call1 := ct1.choose(rand.New(rand.NewSource(seed)), -1)
		if call0 != call1 {
			t.Fatalf("seed=%v iter=%v call=%v/%v", seed, i, call0, call1)
		}
	}
}
