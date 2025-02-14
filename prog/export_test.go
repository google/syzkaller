// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"fmt"
	"math/rand"
	"testing"

	"github.com/google/syzkaller/pkg/testutil"
)

// Export guts for testing.

func init() {
	debug = true
}

var (
	CalcChecksumsCall = calcChecksumsCall
	InitTest          = initTest
	initTargetTest    = InitTargetTest
)

func initRandomTargetTest(t *testing.T, os, arch string) (*Target, rand.Source, int) {
	target := initTargetTest(t, os, arch)
	return target, testutil.RandSource(t), testutil.IterCount()
}

func initTest(t *testing.T) (*Target, rand.Source, int) {
	return initRandomTargetTest(t, "linux", "amd64")
}

func testEachTarget(t *testing.T, fn func(t *testing.T, target *Target)) {
	t.Parallel()
	for _, target := range AllTargets() {
		t.Run(fmt.Sprintf("%v/%v", target.OS, target.Arch), func(t *testing.T) {
			skipTargetRace(t, target)
			t.Parallel()
			fn(t, target)
		})
	}
}

func testEachTargetRandom(t *testing.T, fn func(t *testing.T, target *Target, rs rand.Source, iters int)) {
	t.Parallel()
	targets := AllTargets()
	iters := max(testutil.IterCount()/len(targets), 3)
	rs0 := testutil.RandSource(t)
	for _, target := range targets {
		rs := rand.NewSource(rs0.Int63())
		t.Run(fmt.Sprintf("%v/%v", target.OS, target.Arch), func(t *testing.T) {
			skipTargetRace(t, target)
			t.Parallel()
			fn(t, target, rs, iters)
		})
	}
}

func skipTargetRace(t *testing.T, target *Target) {
	// Race execution is slow and we are getting timeouts on CI.
	// For tests that run for all targets, leave only 2 targets,
	// this should be enough to detect some races.
	if testutil.RaceEnabled && (target.OS != "test" || target.Arch != "64" && target.Arch != "32") {
		t.Skip("skipping all but test/64 targets in race mode")
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
