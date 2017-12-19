// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"github.com/google/syzkaller/pkg/log"
)

func kmemleakInit(enable bool) {
	if enable {
		log.Fatalf("leak checking is not supported on netbsd")
	}
}

func kmemleakScan(report bool) {
}

func checkCompsSupported() (kcov, comps bool) {
	return true, false
}
