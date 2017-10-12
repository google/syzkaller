// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package csource

import (
	"fmt"
	"math/rand"
	"os"
	"reflect"
	"runtime"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

func initTest(t *testing.T) (*prog.Target, rand.Source, int) {
	t.Parallel()
	iters := 1
	seed := int64(time.Now().UnixNano())
	rs := rand.NewSource(seed)
	t.Logf("seed=%v", seed)
	target, err := prog.GetTarget("linux", runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}
	return target, rs, iters
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
	t.Parallel()
	opts := Options{
		Threaded:  true,
		Collide:   true,
		Repeat:    true,
		Procs:     2,
		Sandbox:   "namespace",
		Repro:     true,
		UseTmpDir: true,
	}
	for _, target := range prog.AllTargets() {
		if target.OS == "fuchsia" {
			continue // TODO(dvyukov): support fuchsia
		}
		if target.OS == "windows" {
			continue // TODO(dvyukov): support windows
		}
		target := target
		t.Run(target.OS+"/"+target.Arch, func(t *testing.T) {
			if target.OS == "linux" && target.Arch == "arm" {
				// This currently fails (at least with my arm-linux-gnueabihf-gcc-4.8) with:
				// Assembler messages:
				// Error: alignment too large: 15 assumed
				t.Skip("broken")
			}
			if target.OS == "linux" && target.Arch == "386" {
				// Currently fails on travis with:
				// fatal error: asm/unistd.h: No such file or directory
				t.Skip("broken")
			}
			t.Parallel()
			rs := rand.NewSource(0)
			p := target.GenerateAllSyzProg(rs)
			if len(p.Calls) == 0 {
				t.Skip("no syz syscalls")
			}
			testOne(t, p, opts)
		})
	}
}

func TestOptions(t *testing.T) {
	target, rs, _ := initTest(t)
	syzProg := target.GenerateAllSyzProg(rs)
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
			target, rs, iters := initTest(t)
			t.Logf("opts: %+v", opts)
			for i := 0; i < iters; i++ {
				p := target.Generate(rs, 10, nil)
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
	bin, err := Build(p.Target, "c", srcf)
	if err == NoCompilerErr {
		t.Skip(err)
	}
	if err != nil {
		t.Logf("program:\n%s\n", p.Serialize())
		t.Fatalf("%v", err)
	}
	defer os.Remove(bin)
}
