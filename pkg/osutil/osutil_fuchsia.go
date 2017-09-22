// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build fuchsia

package osutil

func HandleInterrupts(shutdown chan struct{}) {
}

func Abs(path string) string {
	// Getwd is not implemented. Let's hope for best.
	if path == "" {
		return ""
	}
	return "./" + path
}
