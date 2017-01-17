// Copyright 2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package executor

import "testing"

func TestCopyin(t *testing.T) {
	switch res := testCopyin(); {
	case res < 0:
		t.Skip()
	case res > 0:
		t.Fail()
	default:
	}
}

func TestKVM(t *testing.T) {
	switch res := testKVM(); {
	case res < 0:
		t.Skip()
	case res > 0:
		t.Fail()
	default:
	}
}
