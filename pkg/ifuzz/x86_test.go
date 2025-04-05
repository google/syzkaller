// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package ifuzz

import (
	"encoding/hex"
	"strings"
	"testing"

	"github.com/google/syzkaller/pkg/ifuzz/iset"
)

type regTestCase struct {
	text string
	mode iset.Mode
}

// Regression test for x86 instruction decoding.
// nolint: lll
func TestDecodeRegression(t *testing.T) {
	testData := []regTestCase{
		{"46 f7 25 04 49 a3 2c b9 14 01 01 c0 b8 c3 de 66 3f ba 1f 38 8b 0f 0f 30 2e 6e 2e 74 1c 0f 01 30 b9 80 00 00 c0 0f 32 35 00 08 00 00 0f 30 d9 be 45 00 00 00 c7 44 24 00 0b 00 00 00 c7 44 24 02 0e ff ff ff ff 2c 24 c4 23 e9 6c 6e b9 d3", iset.ModeLong64},
		{"0f 30 f0 f7 94 c3 00 0f c7 5f e8 9a 0d 00 ed 00", iset.ModeProt16},
	}
	insnset := iset.Arches[ArchX86]
	for _, test := range testData {
		text, err := hex.DecodeString(strings.ReplaceAll(test.text, " ", ""))
		if err != nil {
			t.Fatalf("invalid hex string")
		}
		for len(text) != 0 {
			size, err := insnset.Decode(test.mode, text)
			if size == 0 || err != nil {
				t.Errorf("failed to decode text: % x", text)
				break
			}
			text = text[size:]
		}
	}
}
