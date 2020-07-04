// Copyright 2019 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"math"
	"math/rand"
	"testing"

	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/prog"
)

type InputTest struct {
	p    *prog.Prog
	sign signal.Signal
	sig  hash.Sig
}

func TestChooseProgram(t *testing.T) {
	rs := rand.NewSource(0)
	r := rand.New(rs)
	target := getTarget(t, "test", "64")
	fuzzer := &Fuzzer{corpusHashes: make(map[hash.Sig]struct{})}

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
		fuzzer.addInputToCorpus(inp.p, inp.sign, inp.sig)
		priorities[inp.p] = int64(len(inp.sign))
	}
	snapshot := fuzzer.snapshot()
	counters := make(map[*prog.Prog]int)
	for it := 0; it < maxIters; it++ {
		counters[snapshot.chooseProgram(r)]++
	}
	for p, prio := range priorities {
		prob := float64(prio) / float64(fuzzer.sumPrios)
		diff := math.Abs(prob*maxIters - float64(counters[p]))
		if diff > eps*maxIters {
			t.Fatalf("the difference (%f) is higher than %f%%", diff, eps*100)
		}
	}
}

func TestAddInputConcurrency(t *testing.T) {
	target := getTarget(t, "test", "64")
	fuzzer := &Fuzzer{corpusHashes: make(map[hash.Sig]struct{})}

	const (
		routines = 10
		iters    = 100
	)

	for i := 0; i < routines; i++ {
		go func() {
			rs := rand.NewSource(0)
			r := rand.New(rs)
			for it := 0; it < iters; it++ {
				inp := generateInput(target, rs, 10, it)
				fuzzer.addInputToCorpus(inp.p, inp.sign, inp.sig)
				snapshot := fuzzer.snapshot()
				snapshot.chooseProgram(r).Clone()
			}
		}()
	}
}

func generateInput(target *prog.Target, rs rand.Source, ncalls, sizeSig int) (inp InputTest) {
	inp.p = target.Generate(rs, ncalls, target.DefaultChoiceTable())
	var raw []uint32
	for i := 1; i <= sizeSig; i++ {
		raw = append(raw, uint32(i))
	}
	inp.sign = signal.FromRaw(raw, 0)
	inp.sig = hash.Hash(inp.p.Serialize())
	return
}

func getTarget(t *testing.T, os, arch string) *prog.Target {
	t.Parallel()
	target, err := prog.GetTarget(os, arch)
	if err != nil {
		t.Fatal(err)
	}
	return target
}
