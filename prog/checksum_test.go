// Copyright 2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog_test

import (
	"testing"

	. "github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

func TestChecksumCalcRandom(t *testing.T) {
	target, rs, iters := InitTest(t)
	ct := target.DefaultChoiceTable()
	for i := 0; i < iters; i++ {
		p := target.Generate(rs, 10, ct)
		for _, call := range p.Calls {
			CalcChecksumsCall(call)
		}
		p.Mutate(rs, 10, ct, nil)
		for _, call := range p.Calls {
			CalcChecksumsCall(call)
		}
	}
}
