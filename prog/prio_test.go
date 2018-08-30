// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"reflect"
	"testing"
)

func TestNormalizePrio(t *testing.T) {
	prios := [][]float32{
		{2, 2, 2},
		{1, 2, 4},
		{1, 2, 0},
	}
	want := [][]float32{
		{1, 1, 1},
		{0.1, 0.4, 1},
		{0.4, 1, 0.1},
	}
	t.Logf("had:  %+v", prios)
	normalizePrio(prios)
	if !reflect.DeepEqual(prios, want) {
		t.Logf("got:  %+v", prios)
		t.Errorf("want: %+v", want)
	}
}
