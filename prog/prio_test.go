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
	target, rs, iters := initTest(t)
	if iters < 100 {
		// Both -short and -race reduce iters to 10 which is not enough
		// for this probabilistic test.
		iters = 100
	}
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
			for it := 0; it < iters*10000; it++ {
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
