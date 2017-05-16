// Copyright 2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"testing"
)

func TestChecksumCalcRandom(t *testing.T) {
	rs, iters := initTest(t)
	for i := 0; i < iters; i++ {
		p := Generate(rs, 10, nil)
		for _, call := range p.Calls {
			calcChecksumsCall(call, i%32)
		}
		for try := 0; try <= 10; try++ {
			p.Mutate(rs, 10, nil, nil)
			for _, call := range p.Calls {
				calcChecksumsCall(call, i%32)
			}
		}
	}
}
