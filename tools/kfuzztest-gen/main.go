// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Small tool for systematically outputting syzlang descriptions of KFuzzTest
// of a vmlinux binary.
package main

import (
	"flag"
	"fmt"

	"github.com/google/syzkaller/pkg/kfuzztest"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/tool"
)

var vmlinuxPath = flag.String("vmlinux", "./vmlinux", "path to vmlinux")

func main() {
	flag.Parse()

	extractor, err := kfuzztest.NewExtractor(*vmlinuxPath)
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
