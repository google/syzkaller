// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package tool contains various helper utilitites useful for implementation of command line tools.
package tool

import (
	"fmt"
	"os"
)

func Failf(msg string, args ...interface{}) {
	fmt.Fprintf(os.Stderr, msg+"\n", args...)
	os.Exit(1)
}

func Fail(err error) {
	Failf("%v", err)
}
