// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package report

import (
	"reflect"
	"testing"
)

func TestParseObjdumpOutput(t *testing.T) {
	rawResponse := `
/tmp/binary:     file format binary


Disassembly of section .data:

00000000 <.data>:
   0:   55                      push   %ebp
   1:   53                      push   %ebx
   2:   31 c0                   xor    %eax,%eax
   4:   e8 f5 bf f7 ff          call   0xfff7bffe
   9:   ff                      (bad)
`
	opcodes := objdumpParseOutput([]byte(rawResponse))
	expected := []DecompiledOpcode{
		{
			Offset:          0,
			Instruction:     "push   %ebp",
			FullDescription: "   0:   55                      push   %ebp",
		},
		{
			Offset:          1,
			Instruction:     "push   %ebx",
			FullDescription: "   1:   53                      push   %ebx",
		},
		{
			Offset:          2,
			Instruction:     "xor    %eax,%eax",
			FullDescription: "   2:   31 c0                   xor    %eax,%eax",
		},
		{
			Offset:          4,
			Instruction:     "call   0xfff7bffe",
			FullDescription: "   4:   e8 f5 bf f7 ff          call   0xfff7bffe",
		},
		{
			Offset:          9,
			Instruction:     "(bad)",
			IsBad:           true,
			FullDescription: "   9:   ff                      (bad)",
		},
	}
	if !reflect.DeepEqual(opcodes, expected) {
		t.Errorf("Expected: %#v, got: %#v", expected, opcodes)
	}
}
