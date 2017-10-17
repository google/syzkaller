// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// mutates mutates a given program and prints result.
package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"math/rand"
	"os"
	"runtime"
	"time"

	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

var (
	flagOS   = flag.String("os", runtime.GOOS, "target os")
	flagArch = flag.String("arch", runtime.GOARCH, "target arch")
	flagSeed = flag.Int("seed", -1, "prng seed")
)

func main() {
	flag.Parse()
	target, err := prog.GetTarget(*flagOS, *flagArch)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v", err)
		os.Exit(1)
	}
	seed := time.Now().UnixNano()
	if *flagSeed != -1 {
		seed = int64(*flagSeed)
	}
	rs := rand.NewSource(seed)
	prios := target.CalculatePriorities(nil)
	ct := target.BuildChoiceTable(prios, nil)
	var p *prog.Prog
	if flag.NArg() == 0 {
		p = target.Generate(rs, 20, ct)
	} else {
		data, err := ioutil.ReadFile(flag.Arg(0))
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to read prog file: %v\n", err)
			os.Exit(1)
		}
		p, err = target.Deserialize(data)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to deserialize the program: %v\n", err)
			os.Exit(1)
		}
		p.Mutate(rs, len(p.Calls)+10, ct, nil)
	}
	fmt.Printf("%s\n", p.Serialize())
}
