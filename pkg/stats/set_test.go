// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package stats

import (
	"fmt"
	"math/rand"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestSet(t *testing.T) {
	a := assert.New(t)
	set := newSet(4, false)
	a.Empty(set.Collect(All))
	_, err := set.RenderHTML()
	a.NoError(err)

	v0 := set.Create("v0", "desc0")
	a.Equal(v0.Val(), 0)
	v0.Add(1)
	a.Equal(v0.Val(), 1)
	v0.Add(1)
	a.Equal(v0.Val(), 2)

	vv1 := 0
	v1 := set.Create("v1", "desc1", Simple, func() int { return vv1 })
	a.Equal(v1.Val(), 0)
	vv1 = 11
	a.Equal(v1.Val(), 11)
	a.Panics(func() { v1.Add(1) })

	v2 := set.Create("v2", "desc2", Console, func(v int, period time.Duration) string {
		return fmt.Sprintf("v2 %v %v", v, period)
	})
	v2.Add(100)

	v3 := set.Create("v3", "desc3", Link("/v3"), NoGraph, Distribution{})
	a.Equal(v3.Val(), 0)
	v3.Add(10)
	a.Equal(v3.Val(), 10)
	v3.Add(20)
	a.Equal(v3.Val(), 15)
	v3.Add(20)
	a.Equal(v3.Val(), 16)
	v3.Add(30)
	a.Equal(v3.Val(), 20)
	v3.Add(30)
	a.Equal(v3.Val(), 22)
	v3.Add(30)
	v3.Add(30)
	a.Equal(v3.Val(), 24)

	v4 := set.Create("v4", "desc4", Rate{}, Graph("graph"))
	v4.Add(10)
	a.Equal(v4.Val(), 10)
	v4.Add(10)
	a.Equal(v4.Val(), 20)

	a.Panics(func() { set.Create("v0", "desc0", float64(1)) })

	ui := set.Collect(All)
	a.Equal(len(ui), 5)
	a.Equal(ui[0], UI{"v2", "desc2", "", Console, "v2 100 1s", 100})
	a.Equal(ui[1], UI{"v1", "desc1", "", Simple, "11", 11})
	a.Equal(ui[2], UI{"v0", "desc0", "", All, "2", 2})
	a.Equal(ui[3], UI{"v3", "desc3", "/v3", All, "24", 24})
	a.Equal(ui[4], UI{"v4", "desc4", "", All, "20 (20/sec)", 20})

	ui1 := set.Collect(Simple)
	a.Equal(len(ui1), 2)
	a.Equal(ui1[0].Name, "v2")
	a.Equal(ui1[1].Name, "v1")

	ui2 := set.Collect(Console)
	a.Equal(len(ui2), 1)
	a.Equal(ui2[0].Name, "v2")

	_, err = set.RenderHTML()
	a.NoError(err)
}

func TestSetRateFormat(t *testing.T) {
	a := assert.New(t)
	set := newSet(4, false)
	v := set.Create("v", "desc", Rate{})
	a.Equal(set.Collect(All)[0].Value, "0 (0/hour)")
	v.Add(1)
	a.Equal(set.Collect(All)[0].Value, "1 (60/min)")
	v.Add(99)
	a.Equal(set.Collect(All)[0].Value, "100 (100/sec)")
}

func TestSetHistoryCounter(t *testing.T) {
	a := assert.New(t)
	set := newSet(4, false)
	v := set.Create("v0", "desc0")
	set.tick()
	hist := func() []float64 { return set.graphs["v0"].lines["v0"].data[:set.historyPos] }
	step := func(n int) []float64 {
		v.Add(n)
		set.tick()
		return hist()
	}
	a.Equal(hist(), []float64{0})
	v.Add(1)
	v.Add(1)
	a.Equal(hist(), []float64{0})
	set.tick()
	a.Equal(hist(), []float64{0, 2})
	v.Add(3)
	a.Equal(hist(), []float64{0, 2})
	set.tick()
	a.Equal(hist(), []float64{0, 2, 5})
	a.Equal(step(-1), []float64{0, 2, 5, 4})
	// Compacted, each new history value will require 2 steps.
	a.Equal(step(7), []float64{2, 5})
	a.Equal(step(-10), []float64{2, 5, 11})
	a.Equal(step(2), []float64{2, 5, 11})
	a.Equal(step(1), []float64{2, 5, 11, 4})
	// 4 steps for each new value.
	a.Equal(step(1), []float64{5, 11})
	a.Equal(step(1), []float64{5, 11})
	a.Equal(step(1), []float64{5, 11})
	a.Equal(step(1), []float64{5, 11, 8})
}

func TestSetHistoryRate(t *testing.T) {
	a := assert.New(t)
	set := newSet(4, false)
	v := set.Create("v0", "desc0", Rate{})
	step := func(n int) []float64 {
		v.Add(n)
		set.tick()
		return set.graphs["v0"].lines["v0"].data[:set.historyPos]
	}
	a.Equal(step(3), []float64{3})
	a.Equal(step(1), []float64{3, 1})
	a.Equal(step(2), []float64{3, 1, 2})
	a.Equal(step(5), []float64{3, 1, 2, 5})
	a.Equal(step(1), []float64{2, 3.5})
	a.Equal(step(2), []float64{2, 3.5, 1.5})
	a.Equal(step(2), []float64{2, 3.5, 1.5})
	a.Equal(step(4), []float64{2, 3.5, 1.5, 3})
	a.Equal(step(1), []float64{2.75, 2.25})
	a.Equal(step(2), []float64{2.75, 2.25})
	a.Equal(step(3), []float64{2.75, 2.25})
	a.Equal(step(4), []float64{2.75, 2.25, 2.5})
}

func TestSetHistoryDistribution(t *testing.T) {
	a := assert.New(t)
	set := newSet(4, false)
	v := set.Create("v0", "desc0", Distribution{})
	step := func(n int) [3][]float64 {
		v.Add(n)
		set.tick()
		var history [3][]float64
		for p, percent := range []int{10, 50, 90} {
			history[p] = make([]float64, set.historyPos)
			for i := 0; i < set.historyPos; i++ {
				hist := set.graphs["v0"].lines["v0"].hist[i]
				if hist != nil {
					history[p][i] = hist.Quantile(float64(percent) / 100)
				}
			}
		}
		return history
	}
	a.Equal(step(3), [3][]float64{{3}, {3}, {3}})
	a.Equal(step(6), [3][]float64{{3, 6}, {3, 6}, {3, 6}})
	a.Equal(step(1), [3][]float64{{3, 6, 1}, {3, 6, 1}, {3, 6, 1}})
	a.Equal(step(2), [3][]float64{{3, 6, 1, 2}, {3, 6, 1, 2}, {3, 6, 1, 2}})
	a.Equal(step(1), [3][]float64{{3, 1}, {3, 1}, {3, 1}})
	a.Equal(step(10), [3][]float64{{3, 1, 1}, {3, 1, 10}, {3, 1, 10}})
}

func TestSetStress(t *testing.T) {
	set := newSet(4, false)
	var stop atomic.Bool
	var seq atomic.Uint64
	start := func(f func()) {
		go func() {
			for !stop.Load() {
				f()
			}
		}()
	}
	for p := 0; p < 2; p++ {
		for _, opt := range []any{Link(""), NoGraph, Rate{}, Distribution{}} {
			opt := opt
			go func() {
				v := set.Create(fmt.Sprintf("v%v", seq.Add(1)), "desc", opt)
				for p1 := 0; p1 < 2; p1++ {
					start(func() { v.Val() })
					start(func() { v.Add(rand.Intn(10000)) })
				}
			}()
		}
		go func() {
			var vv atomic.Uint64
			v := set.Create(fmt.Sprintf("v%v", seq.Add(1)), "desc",
				func() int { return int(vv.Load()) })
			for p1 := 0; p1 < 2; p1++ {
				start(func() { v.Val() })
				start(func() { vv.Store(uint64(rand.Intn(10000))) })
			}
		}()
		start(func() { set.Collect(All) })
		start(func() { set.RenderHTML() })
		start(func() { set.tick() })
	}
	time.Sleep(time.Second)
	stop.Store(true)
}
