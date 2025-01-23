// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package netbsd_test

import (
	"testing"

	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
	"github.com/google/syzkaller/sys/targets"
)

func TestNetBSDNeutralize(t *testing.T) {
	prog.TestDeserializeHelper(t, targets.NetBSD, targets.AMD64, nil, []prog.DeserializeTest{
		{
			In:  `compat_50_mknod(&(0x7f0000000000)='./file0\x00', 0x2001, 0x400)`,
			Out: `compat_50_mknod(&(0x7f0000000000)='./file0\x00', 0x8001, 0x400)`,
		},
	})
}
