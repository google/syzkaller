// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package backend

import (
	"testing"

	"github.com/google/syzkaller/pkg/vminfo"
	"github.com/stretchr/testify/require"
)

func TestMatchPath(t *testing.T) {
	tests := []struct {
		p1   string
		p2   string
		want bool
	}{
		{"arch/x86/kvm/vmx/sgx.h", "arch/x86/kvm/vmx/sgx.h", true},
		{"/build/kernel/arch/x86/kvm/vmx/sgx.h", "arch/x86/kvm/vmx/sgx.h", true},
		{"arch/x86/kvm/vmx/sgx.h", "/build/kernel/arch/x86/kvm/vmx/sgx.h", true},
		{"./fs/ext4/super.c", "fs/ext4/super.c", true},
		{"fs/ext4/super.c", "fs/ext4/inode.c", false},
		{"foo/bar_test.c", "test.c", false},
	}
	for _, tt := range tests {
		require.Equal(t, tt.want, matchPath(tt.p1, tt.p2), "matchPath(%q, %q)", tt.p1, tt.p2)
	}
}

func TestMatchFrames(t *testing.T) {
	frames := []*Frame{
		{PC: 0x100, FuncName: "kvm_vcpu_ioctl", Range: Range{StartLine: 5290}},
		{PC: 0x120, FuncName: "kvm_vcpu_ioctl", Range: Range{StartLine: 5290}},
		{PC: 0x130, FuncName: "kvm_vcpu_ioctl", Range: Range{StartLine: 5314}},
		{PC: 0x200, FuncName: "kvm_arch_vcpu_ioctl", Range: Range{StartLine: 6000}},
	}

	// Exact line match on line 5290 should return both 0x100 and 0x120.
	pcs, err := matchFrames(frames, 5290)
	require.NoError(t, err)
	require.Equal(t, []uint64{0x100, 0x120}, pcs)

	// Target line 5295 is within kvm_vcpu_ioctl, closest preceding line is 5290.
	pcs, err = matchFrames(frames, 5295)
	require.NoError(t, err)
	require.Equal(t, []uint64{0x100, 0x120}, pcs)

	// Target line 5320 is after line 5314 in kvm_vcpu_ioctl, closest preceding line is 5314.
	pcs, err = matchFrames(frames, 5320)
	require.NoError(t, err)
	require.Equal(t, []uint64{0x130}, pcs)

	// Target line 6010 is within kvm_arch_vcpu_ioctl.
	pcs, err = matchFrames(frames, 6010)
	require.NoError(t, err)
	require.Equal(t, []uint64{0x200}, pcs)

	// Line before any frame in the file.
	_, err = matchFrames(frames, 100)
	require.Error(t, err)
	require.Contains(t, err.Error(), "no KCOV coverage PC found for line 100")
}

func TestResolveLineToPCsWithMock(t *testing.T) {
	mod := &vminfo.KernelModule{Name: "", Path: "vmlinux"}
	symbolizeCalls := 0
	impl := &Impl{
		Units: []*CompileUnit{
			{
				ObjectUnit: ObjectUnit{
					Name: "fs/ext4/super.c",
					PCs:  []uint64{0x1000, 0x1010, 0x1020},
				},
				Module: mod,
			},
		},
		Symbolize: func(pcs map[*vminfo.KernelModule][]uint64) ([]*Frame, error) {
			symbolizeCalls++
			var frames []*Frame
			for _, pc := range pcs[mod] {
				switch pc {
				case 0x1000:
					frames = append(frames, &Frame{
						PC:       0x1000,
						Name:     "fs/ext4/super.c",
						FuncName: "ext4_mount",
						Range:    Range{StartLine: 100},
					})
				case 0x1010:
					frames = append(frames, &Frame{
						PC:       0x1010,
						Name:     "fs/ext4/super.c",
						FuncName: "ext4_mount",
						Range:    Range{StartLine: 110},
					})
				case 0x1020:
					frames = append(frames, &Frame{
						PC:       0x1020,
						Name:     "fs/ext4/super.c",
						FuncName: "ext4_mount",
						Range:    Range{StartLine: 120},
					})
				}
			}
			return frames, nil
		},
	}

	// Argument errors.
	_, err := impl.ResolveLineToPCs("", 100)
	require.Error(t, err)
	_, err = impl.ResolveLineToPCs("fs/ext4/super.c", 0)
	require.Error(t, err)

	// Unknown .c file returns an error immediately without invoking Symbolize.
	_, err = impl.ResolveLineToPCs("fs/ext4/unknown.c", 100)
	require.Error(t, err)
	require.Contains(t, err.Error(), `no KCOV coverage points found for file "fs/ext4/unknown.c"`)
	require.Equal(t, 0, symbolizeCalls)

	// Unknown header file triggers fallback to all compile units, invoking Symbolize.
	_, err = impl.ResolveLineToPCs("include/linux/unknown.h", 100)
	require.Error(t, err)
	require.Contains(t, err.Error(), `no KCOV coverage points found for file "include/linux/unknown.h"`)
	require.Equal(t, 1, symbolizeCalls)

	// Exact line match.
	pcs, err := impl.ResolveLineToPCs("fs/ext4/super.c", 110)
	require.NoError(t, err)
	require.Equal(t, []uint64{0x1010}, pcs)

	// Intermediate line inside basic block.
	pcs, err = impl.ResolveLineToPCs("fs/ext4/super.c", 115)
	require.NoError(t, err)
	require.Equal(t, []uint64{0x1010}, pcs)

	// Call again, should use cached impl.Frames.
	pcs, err = impl.ResolveLineToPCs("fs/ext4/super.c", 105)
	require.NoError(t, err)
	require.Equal(t, []uint64{0x1000}, pcs)
}
