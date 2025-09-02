// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Small tool for systematically outputting syzlang descriptions of KFuzzTest
// of a vmlinux binary.
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/google/syzkaller/pkg/kfuzztest"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/tool"
)

func main() {
	usage := func(w io.Writer) {
		fmt.Fprintln(w, "usage: ./kfuzztest-gen /path/to/vmlinux")
	}
	if len(os.Args) != 2 {
		usage(os.Stderr)
		os.Exit(1)
	}

	extractor, err := kfuzztest.NewExtractor(os.Args[1])
	if err != nil {
		tool.Fail(err)
	}
	defer extractor.Close()

	log.Log(0, "extracting ELF data")
	res, err := extractor.ExtractAll()
	if err != nil {
		tool.Fail(err)
	}
	log.Log(0, res.String())

	builder := kfuzztest.NewBuilder(res.Funcs, res.Structs, res.Constraints, res.Annotations)
	desc, err := builder.EmitSyzlangDescription()
	if err != nil {
		tool.Fail(err)
	}
	log.Logf(0, "emitting syzlang description")
	fmt.Println(desc)
}
