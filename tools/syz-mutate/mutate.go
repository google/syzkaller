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
	"time"

	"github.com/google/syzkaller/prog"
)

var (
	flagSeed = flag.Int("seed", -1, "prng seed")
)

func main() {
	flag.Parse()
	if flag.NArg() != 1 {
		fmt.Fprintf(os.Stderr, "usage: mutate program\n")
		os.Exit(1)
	}
	data, err := ioutil.ReadFile(flag.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read prog file: %v\n", err)
		os.Exit(1)
	}
	p, err := prog.Deserialize(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to deserialize the program: %v\n", err)
		os.Exit(1)
	}

	prios := prog.CalculatePriorities(nil)
	ct := prog.BuildChoiceTable(prios, nil)

	seed := time.Now().UnixNano()
	if *flagSeed != -1 {
		seed = int64(*flagSeed)
	}
	rs := rand.NewSource(seed)
	p.Mutate(rs, len(p.Calls)+10, ct, nil)
	fmt.Printf("%s\n", p.Serialize())
}
