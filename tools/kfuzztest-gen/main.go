// Small tool for systematically outputting syzlang descriptions of KFuzzTest
// of a vmlinux binary.
package main

import (
	"flag"
	"fmt"
	"strings"

	"github.com/google/syzkaller/pkg/kfuzztest"
)

var vmlinuxPath = flag.String("vmlinux", "./vmlinux", "path to vmlinux")

func main() {
	flag.Parse()

	extractor, err := kfuzztest.NewExtractor(*vmlinuxPath)
	if err != nil {
		panic(err)
	}

	fmt.Println("extracting ELF data")
	res, err := extractor.ExtractAll()
	if err != nil {
		panic(err)
	}

	fmt.Println("extracted")
	fmt.Printf("\t%d targets\n", len(res.Funcs))
	fmt.Printf("\t%d input structs\n", len(res.Structs))
	fmt.Printf("\t%d constraints\n", len(res.Constraints))
	fmt.Printf("\t%d annotations\n", len(res.Annotations))
	fmt.Printf("from %s\n", *vmlinuxPath)

	fmt.Println("emitting syzlang description")
	fmt.Println(strings.Repeat("-", 75))
	builder := kfuzztest.NewBuilder(res.Funcs, res.Structs, res.Constraints, res.Annotations)
	desc, err := builder.EmitSyzlangDescription()
	if err != nil {
		panic(err)
	}

	fmt.Print(desc)
}
