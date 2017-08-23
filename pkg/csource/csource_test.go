// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package csource

import (
	"fmt"
	"math/rand"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/prog"
)

func initTest(t *testing.T) (rand.Source, int) {
	t.Parallel()
	iters := 1
	seed := int64(time.Now().UnixNano())
	rs := rand.NewSource(seed)
	t.Logf("seed=%v", seed)
	return rs, iters
}

func enumerateField(opt Options, field int) []Options {
	var opts []Options
	s := reflect.ValueOf(&opt).Elem()
	fldName := s.Type().Field(field).Name
	fld := s.Field(field)
	if fldName == "Sandbox" {
		for _, sandbox := range []string{"", "none", "setuid", "namespace"} {
			fld.SetString(sandbox)
			opts = append(opts, opt)
		}
	} else if fldName == "Procs" {
		for _, procs := range []int64{1, 4} {
			fld.SetInt(procs)
			opts = append(opts, opt)
		}
	} else if fldName == "FaultCall" {
		opts = append(opts, opt)
	} else if fldName == "FaultNth" {
		opts = append(opts, opt)
	} else if fld.Kind() == reflect.Bool {
		for _, v := range []bool{false, true} {
			fld.SetBool(v)
			opts = append(opts, opt)
		}
	} else {
		panic(fmt.Sprintf("field '%v' is not boolean", fldName))
	}
	var checked []Options
	for _, opt := range opts {
		if err := opt.Check(); err == nil {
			checked = append(checked, opt)
		}
	}
	return checked
}

func allOptionsSingle() []Options {
	var opts []Options
	fields := reflect.TypeOf(Options{}).NumField()
	for i := 0; i < fields; i++ {
		opts = append(opts, enumerateField(Options{}, i)...)
	}
	return opts
}

func allOptionsPermutations() []Options {
	opts := []Options{Options{}}
	fields := reflect.TypeOf(Options{}).NumField()
	for i := 0; i < fields; i++ {
		var newOpts []Options
		for _, opt := range opts {
			newOpts = append(newOpts, enumerateField(opt, i)...)
		}
		opts = newOpts
	}
	return opts
}

func TestOne(t *testing.T) {
	rs, _ := initTest(t)
	opts := Options{
		Threaded:  true,
		Collide:   true,
		Repeat:    true,
		Procs:     2,
		Sandbox:   "namespace",
		Repro:     true,
		UseTmpDir: true,
	}
	p := prog.GenerateAllSyzProg(rs)
	testOne(t, p, opts)
}

func TestOptions(t *testing.T) {
	rs, _ := initTest(t)
	syzProg := prog.GenerateAllSyzProg(rs)
	t.Logf("syz program:\n%s\n", syzProg.Serialize())
	permutations := allOptionsSingle()
	allPermutations := allOptionsPermutations()
	if testing.Short() {
		r := rand.New(rs)
		for i := 0; i < 32; i++ {
			permutations = append(permutations, allPermutations[r.Intn(len(allPermutations))])
		}
	} else {
		permutations = allPermutations
	}
	for i, opts := range permutations {
		t.Run(fmt.Sprintf("%v", i), func(t *testing.T) {
			rs, iters := initTest(t)
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
	srcf, err := osutil.WriteTempFile(src)
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
