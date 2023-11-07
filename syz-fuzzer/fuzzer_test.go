// Copyright 2019 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"math/rand"
	"testing"

	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
	"github.com/stretchr/testify/assert"
)

type InputTest struct {
	p    *prog.Prog
	sign signal.Signal
	sig  hash.Sig
}

func TestChooseProgram(t *testing.T) {
	rs := rand.NewSource(0)
	r := rand.New(rs)
	target := getTarget(t, targets.TestOS, targets.TestArch64)
	fuzzer := &Fuzzer{corpusHashes: make(map[hash.Sig]struct{})}

	saveInput := func(size int) *prog.Prog {
		inp := generateInput(target, rs, 5, size)
		fuzzer.addInputToCorpus(inp.p, inp.sign, inp.sig)
		return inp.p
	}

	// Three inputs with nested coverage: [[[[D]C]B]A].
	A := saveInput(50)
	B := saveInput(30)
	C := saveInput(10)
	D := saveInput(5)

	selected := map[*prog.Prog]int{}
	total := 1000
	for i := 0; i < total; i++ {
		selected[fuzzer.selector.chooseProgram(r)]++
	}

	t.Logf("%d %d %d %d", selected[A], selected[B], selected[C], selected[D])

	// We should have selected A most of the time as it covers PCs
	// that are not covered by any other prog.
	assert.True(t, selected[A]/selected[B] >= 2)
	assert.True(t, selected[B]/selected[C] >= 2)
	assert.True(t, selected[C] > selected[D])
	assert.True(t, selected[D] > 0)
}

func TestAddInputConcurrency(t *testing.T) {
	target := getTarget(t, targets.TestOS, targets.TestArch64)
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
				fuzzer.selector.chooseProgram(r).Clone()
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
