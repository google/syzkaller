// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"github.com/google/syzkaller/pkg/log"
)

func kmemleakInit() {
	if *flagLeak {
		log.Fatalf("leak checking is not supported on windows")
	}
}

func kmemleakScan(report bool) {
}

func checkCompsSupported() (kcov, comps bool) {
	return false, false
}
