// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"flag"
	"fmt"
	"io/ioutil"
	"os"

	"github.com/google/syzkaller/csource"
	"github.com/google/syzkaller/prog"
)

var (
	flagThreaded = flag.Bool("threaded", false, "create threaded program")
	flagCollide  = flag.Bool("collide", false, "create collide program")
)

func main() {
	flag.Parse()
	if len(flag.Args()) != 1 {
		fmt.Fprintf(os.Stderr, "usage: prog2c [-threaded [-collide]] prog_file\n")
		os.Exit(1)
	}
	data, err := ioutil.ReadFile(flag.Args()[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read prog file: %v\n", err)
		os.Exit(1)
	}
	p, err := prog.Deserialize(data)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to deserialize the program: %v\n", err)
		os.Exit(1)
	}
	opts := csource.Options{
		Threaded: *flagThreaded,
		Collide:  *flagCollide,
	}
	src := csource.Write(p, opts)
	os.Stdout.Write(src)
}
