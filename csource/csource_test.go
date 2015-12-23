// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package csource

import (
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/google/syzkaller/prog"
)

func initTest(t *testing.T) (rand.Source, int) {
	iters := 1000
	if testing.Short() {
		iters = 10
	}
	seed := int64(time.Now().UnixNano())
	rs := rand.NewSource(seed)
	t.Logf("seed=%v", seed)
	return rs, iters
}

func Test(t *testing.T) {
	rs, iters := initTest(t)
	options := []Options{
		Options{},
		Options{Threaded: true},
		Options{Threaded: true, Collide: true},
	}
	for i := 0; i < iters; i++ {
		p := prog.Generate(rs, 10, nil)
		for _, opts := range options {
			testOne(t, p, opts)
		}
	}
}

func testOne(t *testing.T, p *prog.Prog, opts Options) {
	src := Write(p, opts)
	srcf, err := WriteTempFile(src)
	if err != nil {
		t.Fatalf("%v", err)
	}
	defer os.Remove(srcf)
	bin, err := Build(srcf)
	if err != nil {
		t.Fatalf("%v", err)
	}
	defer os.Remove(bin)
}
