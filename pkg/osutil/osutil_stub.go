// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build !linux

package osutil

import (
	"os"
)

func prolongPipe(r, w *os.File) {
}
