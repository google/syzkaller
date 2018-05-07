// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build race

package csource

import (
	"fmt"
	"os"
	"strings"
)

func init() {
	// csource tests consume too much memory under race detector (>1GB),
	// and periodically timeout on Travis. So we skip them.
	for _, arg := range os.Args[1:] {
		if strings.Contains(arg, "-test.short") {
			fmt.Printf("skipping race testing in short mode\n")
			os.Exit(0)
		}
	}
}
