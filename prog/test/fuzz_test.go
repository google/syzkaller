// Copyright 2019 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package test

import (
	"testing"
)

func TestFuzz(t *testing.T) {
	for i, data := range []string{
		`test$length10(&200000000000009`,
		`test$str0(&(0x7f0000000000)='\xz+')`,
		`syz_compare(&AUTO=""/81546506777")`,
		`syz_compare(&AUTO=""/190734863281259)`,
		`syz_compare(&AUTO=""/500000)`,
		`test$vma0(&(0x7f0000000000)=0)`,
		`test$vma0(&(0x7f0000000000)=')`,
		`test$length10(&(0x7f0000009000),AUTO)`,
		`syz_compare(&AUTO=""/2712404)
mutate4()
mutate7()
mutate8()
`,
		`E`,
	} {
		t.Logf("test #%v: %q", i, data)
		inp := []byte(data)[:len(data):len(data)]
		FuzzDeserialize(inp)
		FuzzParseLog(inp)
	}
}
