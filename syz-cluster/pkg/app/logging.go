// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package app

import "log"

// TODO: catch these with monitoring.

func Errorf(fmt string, args ...any) {
	log.Printf(fmt, args...)
}

func Fatalf(fmt string, args ...any) {
	log.Fatalf(fmt, args...)
}
