// Copyright 2019 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"bytes"
	"fmt"
	"math/rand"
	"sort"
	"testing"
)

func TestRotationRandom(t *testing.T) {
	target, rs, _ := initTest(t)
	for _, ncalls := range []int{10, 100, 1000, 1e9} {
		ncalls := ncalls
		rnd := rand.New(rand.NewSource(rs.Int63()))
		t.Run(fmt.Sprint(ncalls), func(t *testing.T) {
			t.Parallel()
			calls0 := selectCalls(target, rnd, ncalls)
			calls := MakeRotator(target, calls0, rnd).Select()
			for call := range calls {
				if !calls0[call] {
					t.Errorf("selected disabled syscall %v", call.Name)
				}
			}
			buf := new(bytes.Buffer)
			var array []*Syscall
			for call := range calls {
				array = append(array, call)
			}
			sort.Slice(array, func(i, j int) bool {
				return array[i].Name < array[j].Name
			})
			for _, call := range array {
				fmt.Fprintf(buf, "%v\n", call.Name)
			}
			t.Logf("calls %v->%v:\n%s", len(calls0), len(calls), buf.Bytes())
		})
	}
}

func TestRotationCoverage(t *testing.T) {
	target, rs, _ := initTest(t)
	calls := make(map[*Syscall]bool)
	counters := make(map[string]int)
	for _, call := range target.Syscalls {
		calls[call] = true
		counters[call.Name] = 0
	}
	rotator := MakeRotator(target, calls, rand.New(rs))
	for iter := 0; iter < 5e3; iter++ {
		for call := range rotator.Select() {
			counters[call.Name]++
		}
	}
	type pair struct {
		name  string
		count int
	}
	var pairs []pair
	remain := len(counters)
	for name, count := range counters {
		pairs = append(pairs, pair{name, count})
		if count != 0 {
			remain--
		}
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].count != pairs[j].count {
			return pairs[i].count > pairs[j].count
		}
		return pairs[i].name < pairs[j].name
	})
	for i, pair := range pairs {
		t.Logf("# %4d: % 4d %v", i, pair.count, pair.name)
	}
	if remain != 0 {
		t.Fatalf("uncovered syscalls: %v", remain)
	}
}

func selectCalls(target *Target, rnd *rand.Rand, ncalls int) map[*Syscall]bool {
retry:
	calls := make(map[*Syscall]bool)
	for _, call := range target.Syscalls {
		calls[call] = true
	}
	for {
		for {
			remove := 0
			switch {
			case len(calls) > ncalls+1000:
				remove = 100
			case len(calls) > ncalls+50:
				remove = 20
			case len(calls) > ncalls:
				remove = 1
			default:
				return calls
			}
			var array []*Syscall
			for call := range calls {
				array = append(array, call)
			}
			sort.Slice(array, func(i, j int) bool {
				return array[i].ID < array[j].ID
			})
			rnd.Shuffle(len(calls), func(i, j int) {
				array[i], array[j] = array[j], array[i]
			})
			for _, call := range array[:remove] {
				delete(calls, call)
			}
			calls, _ = target.transitivelyEnabled(calls)
			if len(calls) == 0 {
				goto retry
			}
		}
	}
}
