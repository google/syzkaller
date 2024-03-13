// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package corpus

import (
	"context"
	"math"
	"math/rand"
	"testing"

	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

func TestChooseProgram(t *testing.T) {
	rs := rand.NewSource(0)
	r := rand.New(rs)
	target := getTarget(t, targets.TestOS, targets.TestArch64)
	corpus := NewCorpus(context.Background())

	const (
		maxIters   = 1000
		sizeCorpus = 1000
		eps        = 0.01
	)

	priorities := make(map[*prog.Prog]int64)
	for i := 0; i < sizeCorpus; i++ {
		sizeSig := i + 1
		if sizeSig%250 == 0 {
			sizeSig = 0
		}
		inp := generateInput(target, rs, 10, sizeSig)
		corpus.Save(inp)
		priorities[inp.Prog] = int64(len(inp.Signal))
	}
	counters := make(map[*prog.Prog]int)
	for it := 0; it < maxIters; it++ {
		counters[corpus.ChooseProgram(r)]++
	}
	for p, prio := range priorities {
		prob := float64(prio) / float64(corpus.sumPrios)
		diff := math.Abs(prob*maxIters - float64(counters[p]))
		if diff > eps*maxIters {
			t.Fatalf("the difference (%f) is higher than %f%%", diff, eps*100)
		}
	}
}
