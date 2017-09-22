// Copyright 2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build linux

package executor

import "testing"

func testWrapper(t *testing.T, f func() int) {
	switch res := f(); {
	case res < 0:
		t.Skip()
	case res > 0:
		t.Fail()
	default:
	}
}

func TestCopyin(t *testing.T) {
	testWrapper(t, testCopyin)
}

func TestCsumInet(t *testing.T) {
	testWrapper(t, testCsumInet)
}

func TestCsumInetAcc(t *testing.T) {
	testWrapper(t, testCsumInetAcc)
}

func TestKVM(t *testing.T) {
	testWrapper(t, testKVM)
}
