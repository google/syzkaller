// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package corpus

import (
	"context"
	"math/rand"
	"testing"

	"github.com/google/syzkaller/pkg/signal"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
	"github.com/stretchr/testify/assert"
)

func TestCorpusOperation(t *testing.T) {
	// Basic corpus functionality.
	target := getTarget(t, targets.TestOS, targets.TestArch64)
	ch := make(chan NewItemEvent)
	corpus := NewMonitoredCorpus(context.Background(), ch)

	// First program is saved.
	rs := rand.NewSource(0)
	inp1 := generateInput(target, rs, 5)
	go corpus.Save(inp1)
	event := <-ch
	progData := inp1.Prog.Serialize()
	assert.Equal(t, progData, event.ProgData)
	assert.Equal(t, false, event.Exists)

	// Second program is saved for every its call.
	inp2 := generateInput(target, rs, 5)
	progData = inp2.Prog.Serialize()
	for i := range len(inp2.Prog.Calls) {
		inp2.Call = i
		go corpus.Save(inp2)
		event := <-ch
		assert.Equal(t, progData, event.ProgData)
		assert.Equal(t, i != 0, event.Exists)
	}

	// Verify that we can query corpus items.
	items := corpus.Items()
	assert.Len(t, items, 2)
	for _, item := range items {
		assert.Equal(t, item, corpus.Item(item.Sig))
	}

	// Verify the total signal.
	assert.Equal(t, 5, corpus.StatSignal.Val())
	assert.Equal(t, 2, corpus.StatProgs.Val())

	corpus.Minimize(true)
}

func TestCorpusCoverage(t *testing.T) {
	target := getTarget(t, targets.TestOS, targets.TestArch64)
	ch := make(chan NewItemEvent)
	corpus := NewMonitoredCorpus(context.Background(), ch)
	rs := rand.NewSource(0)

	inp := generateInput(target, rs, 5)
	inp.Cover = []uint64{10, 11}
	go corpus.Save(inp)
	event := <-ch
	assert.Equal(t, []uint64{10, 11}, event.NewCover)

	inp.Call = 1
	inp.Cover = []uint64{11, 12}
	go corpus.Save(inp)
	event = <-ch
	assert.Equal(t, []uint64{12}, event.NewCover)

	// Check the total corpus size.
	assert.Equal(t, corpus.StatCover.Val(), 3)
}

func TestFocusAreaStatsIncludeAllArea(t *testing.T) {
	target := getTarget(t, targets.TestOS, targets.TestArch64)
	corpus := NewFocusedCorpus(context.Background(), nil, []FocusArea{
		{
			Name: "dummy",
			CoverPCs: map[uint64]struct{}{
				42: {},
			},
			Weight: 10,
		},
		{
			Weight: 1,
		},
		{
			CoverPCs: map[uint64]struct{}{
				42: {},
			},
			Weight: 1,
		},
	})
	rs := rand.NewSource(0)

	inp := generateInput(target, rs, 5)
	inp.Cover = []uint64{42}
	corpus.Save(inp)

	inp = generateInput(target, rs, 5)
	inp.Cover = []uint64{100}
	corpus.Save(inp)

	assert.Equal(t, map[string]int{
		"dummy":          1,
		allFocusAreaName: 2,
	}, corpus.ProgsPerArea())
}

func TestFocusAreaStatsDoNotDuplicateExistingProgram(t *testing.T) {
	target := getTarget(t, targets.TestOS, targets.TestArch64)
	corpus := NewFocusedCorpus(context.Background(), nil, []FocusArea{
		{
			Name: "area",
			CoverPCs: map[uint64]struct{}{
				1: {},
				2: {},
			},
			Weight: 1,
		},
	})
	rs := rand.NewSource(0)

	inp := generateInput(target, rs, 5)
	inp.Cover = []uint64{1}
	corpus.Save(inp)
	assert.Equal(t, map[string]int{"area": 1}, corpus.ProgsPerArea())

	inp.Cover = []uint64{2}
	inp.Signal = signal.FromRaw([]uint64{2}, 0)
	corpus.Save(inp)

	assert.Equal(t, map[string]int{"area": 1}, corpus.ProgsPerArea())
}

func TestFocusAreaStatsSurviveMinimize(t *testing.T) {
	target := getTarget(t, targets.TestOS, targets.TestArch64)
	corpus := NewFocusedCorpus(context.Background(), nil, []FocusArea{
		{
			Name: "first",
			CoverPCs: map[uint64]struct{}{
				1: {},
				2: {},
			},
			Weight: 1,
		},
		{
			Name: "second",
			CoverPCs: map[uint64]struct{}{
				2: {},
				3: {},
			},
			Weight: 1,
		},
	})
	rs := rand.NewSource(0)

	inp := generateInput(target, rs, 5)
	inp.Cover = []uint64{2}
	corpus.Save(inp)
	assert.Equal(t, map[string]int{
		"first":  1,
		"second": 1,
	}, corpus.ProgsPerArea())

	corpus.Minimize(true)

	assert.Equal(t, map[string]int{
		"first":  1,
		"second": 1,
	}, corpus.ProgsPerArea())
}

func TestCorpusSaveConcurrency(t *testing.T) {
	target := getTarget(t, targets.TestOS, targets.TestArch64)
	corpus := NewCorpus(context.Background())

	const (
		routines = 10
		iters    = 100
	)

	for range routines {
		go func() {
			rs := rand.NewSource(0)
			r := rand.New(rs)
			for it := range iters {
				inp := generateInput(target, rs, it)
				corpus.Save(inp)
				corpus.ChooseProgram(r).Clone()
			}
		}()
	}
}

func generateInput(target *prog.Target, rs rand.Source, sizeSig int) NewInput {
	return generateRangedInput(target, rs, 1, sizeSig)
}

func generateRangedInput(target *prog.Target, rs rand.Source, sigFrom, sigTo int) NewInput {
	enabled := map[*prog.Syscall]bool{
		target.SyscallMap["test$manual"]: true,
	}
	ct := target.BuildChoiceTable(nil, enabled)
	p := target.Generate(rs, 5, ct)
	var raw []uint64
	for i := sigFrom; i <= sigTo; i++ {
		raw = append(raw, uint64(i))
	}
	return NewInput{
		Prog:   p,
		Call:   int(rs.Int63() % int64(len(p.Calls))),
		Signal: signal.FromRaw(raw, 0),
		Cover:  raw,
	}
}

func getTarget(t *testing.T, os, arch string) *prog.Target {
	t.Parallel()
	target, err := prog.GetTarget(os, arch)
	if err != nil {
		t.Fatal(err)
	}
	return target
}
