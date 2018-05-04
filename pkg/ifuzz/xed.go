// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// XedDecode is required for tests, but it requires Intel XED library installed, so it is disabled by default.
// To run full tests, check out and build github.com/intelxed/xed, then run:
// INTELXED=/path/to/intelxed CGO_CFLAGS="-I $INTELXED/xed/include/public \
//	-I $INTELXED/build/obj" CGO_LDFLAGS="$INTELXED/build/obj/libxed.a" \
//	go test -v -tags xed

// +build xed

package ifuzz

/*
#include "xed-interface.h"

int xedDecode(int mode, int addrsize, void* text, int size, const char** error) {
  xed_decoded_inst_t xedd;
  xed_decoded_inst_zero(&xedd);
  xed_decoded_inst_set_mode(&xedd, mode, addrsize);
  xed_error_enum_t err = xed_decode(&xedd, text, size);
  if (err != XED_ERROR_NONE) {
    if (error)
      *error = xed_error_enum_t2str(err);
    return 0;
  }
  return xed_decoded_inst_get_length(&xedd);
}
*/
import "C"

import (
	"errors"
	"unsafe"
)

func init() {
	C.xed_tables_init()
	XedDecode = xedDecode
}

func xedDecode(mode int, text []byte) (int, error) {
	xedMode := 0
	xedAddr := 0
	switch mode {
	case ModeLong64:
		xedMode = C.XED_MACHINE_MODE_LONG_64
		xedAddr = C.XED_ADDRESS_WIDTH_64b
	case ModeProt32:
		xedMode = C.XED_MACHINE_MODE_LONG_COMPAT_32
		xedAddr = C.XED_ADDRESS_WIDTH_32b
	case ModeProt16:
		xedMode = C.XED_MACHINE_MODE_LONG_COMPAT_16
		xedAddr = C.XED_ADDRESS_WIDTH_16b
	case ModeReal16:
		xedMode = C.XED_MACHINE_MODE_REAL_16
		xedAddr = C.XED_ADDRESS_WIDTH_16b
	default:
		panic("bad mode")
	}
	var errorStr *C.char
	res := C.xedDecode(C.int(xedMode), C.int(xedAddr), unsafe.Pointer(&text[0]), C.int(len(text)), &errorStr)
	if res == 0 {
		return 0, errors.New(C.GoString(errorStr))
	}
	return int(res), nil
}
