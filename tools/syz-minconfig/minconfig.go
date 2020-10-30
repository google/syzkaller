// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// syz-minconfig is a tool for manual checking of config minimization functionality in pkg/kconfig/minimize.go.
// Example use:
// $ go run tools/syz-minconfig/minconfig.go -sourcedir /src/linux -configs CAIF_NETDEV,CAIF_USB \
//	-base dashboard/config/linux/upstream-kasan-base.config \
//	-full dashboard/config/linux/upstream-kasan.config \
package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/google/syzkaller/pkg/kconfig"
	"github.com/google/syzkaller/sys/targets"
)

func main() {
	var (
		flagSourceDir = flag.String("sourcedir", "", "kernel sources dir")
		flagBase      = flag.String("base", "", "baseline config")
		flagFull      = flag.String("full", "", "full config")
		flagConfigs   = flag.String("configs", "", "comma-separated list of configs for the crash predicate")
		flagArch      = flag.String("arch", runtime.GOARCH, "kernel arch")
	)
	flag.Parse()
	kconf, err := kconfig.Parse(targets.Get("linux", *flagArch), filepath.Join(*flagSourceDir, "Kconfig"))
	if err != nil {
		failf("%v", err)
	}
	base, err := kconfig.ParseConfig(*flagBase)
	if err != nil {
		failf("%v", err)
	}
	full, err := kconfig.ParseConfig(*flagFull)
	if err != nil {
		failf("%v", err)
	}
	pred := func(candidate *kconfig.ConfigFile) (bool, error) {
		for _, cfg := range strings.Split(*flagConfigs, ",") {
			if candidate.Value(cfg) == kconfig.No {
				return false, nil
			}
		}
		return true, nil
	}
	res, err := kconf.Minimize(base, full, pred, os.Stderr)
	if err != nil {
		failf("%v", err)
	}
	os.Stdout.Write(res.Serialize())
}

func failf(msg string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, msg+"\n", args...)
	os.Exit(1)
}
