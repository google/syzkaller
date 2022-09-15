// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package linux

import (
	"testing"

	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

func TestSyzMountImageNeutralize(t *testing.T) {
	prog.TestDeserializeHelper(t, targets.Linux, targets.AMD64, nil, []prog.DeserializeTest{
		{
			// A valid call, nothing should change.
			In: `syz_mount_image$bfs(&(0x7f0000000000)='bfs\x00', &(0x7f0000000100)='./file0\x00', 0x2220, 0x2, &(0x7f0000000200)=[{&(0x7f0000010000)="cefaad1bc0210000ff0f0000ffffffffffffffffffffffffffffffff73797a6b616c73797a6b616c00"/64, 0x40, 0x0}, {&(0x7f0000010040)="0200000011000000140000001f22000002000000ed4100000000000001000000020000005ffb19635ffb19635ffb196300"/64, 0x40, 0x200}], 0x0, &(0x7f00000100a0)={[], [], 0x0}, 0x0)`,
		},
		{
			// Invalid total size.
			In: `syz_mount_image$bfs(&(0x7f0000000000)='bfs\x00', &(0x7f0000000100)='./file1\x00', 0x20, 0x2, &(0x7f0000000200)=[{&(0x7f0000010000)="cefaad1bc0210000ff0f0000ffffffffffffffffffffffffffffffff73797a6b616c73797a6b616c00"/64, 0x40, 0x0}, {&(0x7f0000010040)="0200000011000000140000001f22000002000000ed4100000000000001000000020000005ffb19635ffb19635ffb196300"/64, 0x40, 0x200}], 0x0, &(0x7f00000100a0)={[], [], 0x0}, 0x0)`,
			// It should be able to fix up the size.
			Out: `syz_mount_image$bfs(&(0x7f0000000000)='bfs\x00', &(0x7f0000000100)='./file1\x00', 0x240, 0x2, &(0x7f0000000200)=[{&(0x7f0000010000)="cefaad1bc0210000ff0f0000ffffffffffffffffffffffffffffffff73797a6b616c73797a6b616c00"/64, 0x40, 0x0}, {&(0x7f0000010040)="0200000011000000140000001f22000002000000ed4100000000000001000000020000005ffb19635ffb19635ffb196300"/64, 0x40, 0x200}], 0x0, &(0x7f00000100a0)={[], [], 0x0}, 0x0)`,
		},
		{
			// Overflow over the max image size.
			In: `syz_mount_image$bfs(&(0x7f0000000000)='bfs\x00', &(0x7f0000000100)='./file2\x00', 0x8200000, 0x2, &(0x7f0000000200)=[{&(0x7f0000010000)="cefaad1bc0210000ff0f0000ffffffffffffffffffffffffffffffff73797a6b616c73797a6b616c00"/64, 0x40, 0x0}, {&(0x7f0000010040)="0200000011000000140000001f22000002000000ed4100000000000001000000020000005ffb19635ffb19635ffb196300"/64, 0x400, 0x80fffff}], 0x0, &(0x7f00000100a0)={[], [], 0x0}, 0x0)`,
			// It should shift the overflowing segment and adjust the total size.
			Out: `syz_mount_image$bfs(&(0x7f0000000000)='bfs\x00', &(0x7f0000000100)='./file2\x00', 0x8100000, 0x2, &(0x7f0000000200)=[{&(0x7f0000010000)="cefaad1bc0210000ff0f0000ffffffffffffffffffffffffffffffff73797a6b616c73797a6b616c00"/64, 0x40, 0x0}, {&(0x7f0000010040)="0200000011000000140000001f22000002000000ed4100000000000001000000020000005ffb19635ffb19635ffb196300"/64, 0x40, 0x80fffc0}], 0x0, &(0x7f00000100a0)={[], [], 0x0}, 0x0)`,
		},
		{
			// Invalid offset.
			In: `syz_mount_image$bfs(&(0x7f0000000000)='bfs\x00', &(0x7f0000000100)='./file1\x00', 0x20, 0x2, &(0x7f0000000200)=[{&(0x7f0000010000)="cefaad1bc0210000ff0f0000ffffffffffffffffffffffffffffffff73797a6b616c73797a6b616c00"/64, 0x40, 0x0}, {&(0x7f0000010040)="0200000011000000140000001f22000002000000ed4100000000000001000000020000005ffb19635ffb19635ffb196300"/64, 0x40, 0x9100000}], 0x0, &(0x7f00000100a0)={[], [], 0x0}, 0x0)`,
			// The segment is deleted.
			Out: `syz_mount_image$bfs(&(0x7f0000000000)='bfs\x00', &(0x7f0000000100)='./file1\x00', 0x40, 0x1, &(0x7f0000000200)=[{&(0x7f0000010000)="cefaad1bc0210000ff0f0000ffffffffffffffffffffffffffffffff73797a6b616c73797a6b616c00"/64, 0x40, 0x0}], 0x0, &(0x7f00000100a0)={[], [], 0x0}, 0x0)`,
		},
	})
}
