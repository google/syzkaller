// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

//go:build linux && cgo

package clangtoolimpl

/*
extern int syz_declextract_main(int argc, char** argv);
*/
import "C"

import (
	"unsafe"

	"github.com/google/syzkaller/pkg/clangtool"
)

func init() {
	clangtool.Register(Tool, func() {
		clangtool.RunCMain(func(argc int, argv unsafe.Pointer) int {
			return int(C.syz_declextract_main(C.int(argc), (**C.char)(argv)))
		})
	})
}
