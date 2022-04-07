// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package tool

import (
	"reflect"
	"strings"
)

func FuzzParseFlags(data []byte) int {
	flags, err := deserializeFlags(string(data))
	if err != nil {
		return 0
	}
	value := serializeFlags(flags)
	if strings.IndexByte(value, ' ') != -1 {
		panic("flags contain space")
	}
	flags1, err := deserializeFlags(value)
	if err != nil {
		panic(err)
	}
	if !reflect.DeepEqual(flags, flags1) {
		panic("changed")
	}
	return 1
}
