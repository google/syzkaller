// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"fmt"
	"math/rand"
	"os"
	"testing"
	"time"
)

// Export guts for testing.

func init() {
	debug = true
}

var (
	CalcChecksumsCall = calcChecksumsCall
	InitTest          = initTest
)

func initTargetTest(t *testing.T, os, arch string) *Target {
	t.Parallel()
	target, err := GetTarget(os, arch)
	if err != nil {
		t.Fatal(err)
	}
	return target
}

func randSource(t *testing.T) rand.Source {
	seed := time.Now().UnixNano()
	if os.Getenv("TRAVIS") != "" {
		seed = 0 // required for deterministic coverage reports
	}
	t.Logf("seed=%v", seed)
	return rand.NewSource(seed)
}

func iterCount() int {
	iters := 1000
	if testing.Short() {
		iters /= 10
	}
	if raceEnabled {
		iters /= 10
	}
	return iters
}

func initRandomTargetTest(t *testing.T, os, arch string) (*Target, rand.Source, int) {
	target := initTargetTest(t, os, arch)
	return target, randSource(t), iterCount()
}

func initTest(t *testing.T) (*Target, rand.Source, int) {
	return initRandomTargetTest(t, "linux", "amd64")
}

func testEachTarget(t *testing.T, fn func(t *testing.T, target *Target)) {
	t.Parallel()
	for _, target := range AllTargets() {
		target := target
		t.Run(fmt.Sprintf("%v/%v", target.OS, target.Arch), func(t *testing.T) {
			t.Parallel()
			fn(t, target)
		})
	}
}

func testEachTargetRandom(t *testing.T, fn func(t *testing.T, target *Target, rs rand.Source, iters int)) {
	t.Parallel()
	targets := AllTargets()
	iters := iterCount()
	iters /= len(targets)
	if iters < 3 {
		iters = 3
	}
	rs0 := randSource(t)
	for _, target := range targets {
		target := target
		rs := rand.NewSource(rs0.Int63())
		t.Run(fmt.Sprintf("%v/%v", target.OS, target.Arch), func(t *testing.T) {
			t.Parallel()
			fn(t, target, rs, iters)
		})
	}
}

func initBench(b *testing.B) (*Target, func()) {
	olddebug := debug
	debug = false
	target, err := GetTarget("linux", "amd64")
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	return target, func() { debug = olddebug }
}
