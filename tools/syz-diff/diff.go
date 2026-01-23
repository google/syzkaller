// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"flag"
	"os"

	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/manager"
	"github.com/google/syzkaller/pkg/manager/diff"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/vm"
)

var (
	flagBaseConfig = flag.String("base", "", "base config")
	flagNewConfig  = flag.String("new", "", "new config (treated as the main one)")
	flagDebug      = flag.Bool("debug", false, "dump all VM output to console")
	flagPatch      = flag.String("patch", "", "a git patch")
)

func main() {
	if !prog.GitRevisionKnown() {
		log.Fatalf("bad syz-diff build: build with make, run bin/syz-diff")
	}
	flag.Parse()
	log.EnableLogCaching(1000, 1<<20)

	baseCfg, err := mgrconfig.LoadFile(*flagBaseConfig)
	if err != nil {
		log.Fatalf("base config: %v", err)
	}

	newCfg, err := mgrconfig.LoadFile(*flagNewConfig)
	if err != nil {
		log.Fatalf("new config: %v", err)
	}

	if *flagPatch != "" {
		data, err := os.ReadFile(*flagPatch)
		if err != nil {
			log.Fatal(err)
		}
		diff.PatchFocusAreas(newCfg, [][]byte{data}, nil, nil)
	}

	ctx := vm.ShutdownCtx()
	err = diff.Run(ctx, baseCfg, newCfg, diff.Config{
		Store: &manager.DiffFuzzerStore{BasePath: newCfg.Workdir},
		Debug: *flagDebug,
	})
	if err != nil {
		log.Fatal(err)
	}
}
