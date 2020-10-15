// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package kconfig

import (
	"fmt"
	"testing"
)

func TestParseKConfig(t *testing.T) {
	type Test struct {
		in string
	}
	tests := []Test{
		{
			in: `
mainmenu "test"
config FOO
	default "$(shell,$(srctree)/scripts/gcc-plugin.sh "$(preferred-plugin-hostcc)" "$(HOSTCXX)" "$(CC)")" if CC_IS_GCC
`,
		},
	}
	for i, test := range tests {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			kconf, err := ParseData([]byte(test.in), "Kconfig")
			if err != nil {
				t.Fatal(err)
			}
			_ = kconf
		})
	}
}

func TestFuzzParseKConfig(t *testing.T) {
	for _, data := range []string{
		``,
	} {
		FuzzParseKConfig([]byte(data)[:len(data):len(data)])
	}
}
