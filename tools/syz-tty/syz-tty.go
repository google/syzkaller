// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// syz-tty is utility for testing of usb console reading code. Usage:
//   $ syz-tty /dev/ttyUSBx
// This should dump device console output.
package main

import (
	"fmt"
	"io"
	"os"

	"github.com/google/syzkaller/vm/vmimpl"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "usage: %v /dev/ttyUSBx\n", os.Args[0])
		os.Exit(1)
	}
	con, err := vmimpl.OpenConsole(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to open console: %v\n", err)
		os.Exit(1)
	}
	defer con.Close()
	io.Copy(os.Stdout, con)
}
