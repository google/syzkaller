// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"math/rand"
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

func initRandomTargetTest(t *testing.T, os, arch string) (*Target, rand.Source, int) {
	target := initTargetTest(t, os, arch)
	iters := 10000
	if testing.Short() {
		iters = 100
	}
	seed := int64(time.Now().UnixNano())
	rs := rand.NewSource(seed)
	t.Logf("seed=%v", seed)
	return target, rs, iters
}

func initTest(t *testing.T) (*Target, rand.Source, int) {
	return initRandomTargetTest(t, "linux", "amd64")
}
