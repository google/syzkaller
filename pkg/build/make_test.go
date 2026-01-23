// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package build

import (
	"testing"

	"github.com/google/syzkaller/sys/targets"
	"github.com/stretchr/testify/assert"
)

func TestLinuxMakeArgsLLVM(t *testing.T) {
	target := targets.Get(targets.Linux, targets.AMD64)
	args := LinuxMakeArgs(target, "clang", "ld.lld", "", "", 1)

	assert.Contains(t, args, "LLVM=1")
	assert.Contains(t, args, "LLVM_IAS=1")
	assert.Contains(t, args, "KCFLAGS=-mllvm -enable-bb-addr-map")
}
