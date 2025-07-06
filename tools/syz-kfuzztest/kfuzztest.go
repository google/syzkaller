package main

import (
	"flag"
	"fmt"
	"github.com/google/syzkaller/pkg/kfuzztest"
)

var (
	vmlinuxPath = flag.String("vmlinux", "", "Path to vmlinux binary.")
)

func main() {
	flag.Parse()

	extractor, err := kfuzztest.NewExtractor(*vmlinuxPath)
	if err != nil {
		panic(err)
	}
	funcs, structs, err := extractor.ExtractAll()
	if err != nil {
		panic(err)
	}

	fmt.Printf("len(funcs) = %d, len(structs) = %d\n", len(funcs), len(structs))

	builder := kfuzztest.NewBuilder(funcs, structs)
	desc := builder.EmitSyzlangDescription()
	fmt.Print(desc)
}
