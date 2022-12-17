// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package testutil

import (
	"math/rand"
	"os"
	"strconv"
	"testing"
	"time"
)

func IterCount() int {
	iters := 1000
	if testing.Short() {
		iters /= 10
	}
	if RaceEnabled {
		iters /= 10
	}
	return iters
}

func RandSource(t *testing.T) rand.Source {
	seed := time.Now().UnixNano()
	if fixed := os.Getenv("SYZ_SEED"); fixed != "" {
		seed, _ = strconv.ParseInt(fixed, 0, 64)
	}
	if os.Getenv("CI") != "" {
		seed = 0 // required for deterministic coverage reports
	}
	t.Logf("seed=%v", seed)
	return rand.NewSource(seed)
}

func RandMountImage(r *rand.Rand) []byte {
	const maxLen = 1 << 20 // 1 MB.
	len := r.Intn(maxLen)
	slice := make([]byte, len)
	r.Read(slice)
	return slice
}
