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
	//AssignSizesCall   = assignSizesCall
	//DefaultArg        = defaultArg
	InitTest = initTest
)

/*
func PtrSize() uint64 {
	return ptrSize
}

func DataOffset() uint64 {
	return dataOffset
}

func PageSize() uint64 {
	return pageSize
}
*/

func initTest(t *testing.T) (*Target, rand.Source, int) {
	t.Parallel()
	iters := 10000
	if testing.Short() {
		iters = 100
	}
	seed := int64(time.Now().UnixNano())
	rs := rand.NewSource(seed)
	t.Logf("seed=%v", seed)
	target, err := GetTarget("linux", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	return target, rs, iters
}
