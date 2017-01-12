// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package csource

import (
	"fmt"
	"math/rand"
	"os"
	"testing"
	"time"

	"github.com/google/syzkaller/fileutil"
	"github.com/google/syzkaller/prog"
)

func initTest(t *testing.T) (rand.Source, int) {
	iters := 10
	if testing.Short() {
		iters = 1
	}
	seed := int64(time.Now().UnixNano())
	rs := rand.NewSource(seed)
	t.Logf("seed=%v", seed)
	return rs, iters
}

func allOptionsPermutations() []Options {
	var options []Options
	var opt Options
	for _, opt.Threaded = range []bool{false, true} {
		for _, opt.Collide = range []bool{false, true} {
			for _, opt.Repeat = range []bool{false, true} {
				for _, opt.Repro = range []bool{false, true} {
					for _, opt.Procs = range []int{1, 4} {
						for _, opt.Sandbox = range []string{"none", "setuid", "namespace"} {
							if opt.Collide && !opt.Threaded {
								continue
							}
							if !opt.Repeat && opt.Procs != 1 {
								continue
							}
							if testing.Short() && opt.Procs != 1 {
								continue
							}
							options = append(options, opt)
						}
					}
				}
			}
		}
	}
	return options
}

func TestSyz(t *testing.T) {
	rs, _ := initTest(t)
	opts := Options{
		Threaded: true,
		Collide:  true,
		Repeat:   true,
		Procs:    2,
		Sandbox:  "namespace",
		Repro:    true,
	}
	p := prog.GenerateAllSyzProg(rs)
	testOne(t, p, opts)
}

func Test(t *testing.T) {
	rs, iters := initTest(t)
	syzProg := prog.GenerateAllSyzProg(rs)
	t.Logf("syz program:\n%s\n", syzProg.Serialize())
	for i, opts := range allOptionsPermutations() {
		t.Run(fmt.Sprintf("%v", i), func(t *testing.T) {
			t.Logf("opts: %+v", opts)
			for i := 0; i < iters; i++ {
				p := prog.Generate(rs, 10, nil)
				testOne(t, p, opts)
			}
			testOne(t, syzProg, opts)
		})
	}
}

func testOne(t *testing.T, p *prog.Prog, opts Options) {
	src, err := Write(p, opts)
	if err != nil {
		t.Logf("program:\n%s\n", p.Serialize())
		t.Fatalf("%v", err)
	}
	srcf, err := fileutil.WriteTempFile(src)
	if err != nil {
		t.Logf("program:\n%s\n", p.Serialize())
		t.Fatalf("%v", err)
	}
	defer os.Remove(srcf)
	bin, err := Build("c", srcf)
	if err != nil {
		t.Logf("program:\n%s\n", p.Serialize())
		t.Fatalf("%v", err)
	}
	defer os.Remove(bin)
}
