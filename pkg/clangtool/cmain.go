// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

//go:build linux && cgo

package clangtool

/*
#include <stdlib.h>
*/
import "C"
import (
	"os"
	"unsafe"
)

// RunCMain executes a C main function, managing argc/argv conversion and cleanup.
// It will call os.Exit with the result of mainFunc.
func RunCMain(mainFunc func(argc int, argv unsafe.Pointer) int) {
	args := os.Args
	argc := C.int(len(args))
	argv := make([]*C.char, len(args))
	for i, arg := range args {
		argv[i] = C.CString(arg)
	}
	var argvPtr **C.char
	if len(argv) > 0 {
		argvPtr = (**C.char)(unsafe.Pointer(&argv[0]))
	}
	res := mainFunc(int(argc), unsafe.Pointer(argvPtr))
	for _, ptr := range argv {
		C.free(unsafe.Pointer(ptr))
	}
	os.Exit(res)
}
