// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package lists

import (
	"testing"

	"github.com/google/syzkaller/pkg/subsystem"
	"github.com/stretchr/testify/assert"
)

// nolint: lll
func TestLinuxUpstreamSubsystems(t *testing.T) {
	list := subsystem.GetList("linux")
	if list == nil {
		t.Fatalf("the list is not registered")
	}
	group := subsystem.MakeExtractor(list)

	// For now let's keep all the regression tests in this .go file, but if later
	// it turns out there are just too many of them, we will need to store it in
	// separate files.
	tests := []struct {
		name    string
		crashes []*subsystem.Crash
		expect  []string
	}{
		{
			name: `a pure xfs bug`,
			crashes: []*subsystem.Crash{
				{
					GuiltyPath: `fs/xfs/libxfs/xfs_btree.c`,
					SyzRepro: []byte(`# https://syzkaller.appspot.com/bug?id=e2907149c69cbccae0842eb502b8af4f6fac52a0
# See https://goo.gl/kgGztJ for information about syzkaller reproducers.
#{"procs":1,"slowdown":1,"sandbox":"","sandbox_arg":0,"close_fds":false}
syz_mount_image$xfs(&(0x7f0000000100), &(0x7f0000009640)='./file2\x00', 0x200800, &(0x7f0000000240)=ANY=[], 0x1, 0x9712, &(0x7f0000009680)="$eJzs3Qm4pnPhuPH=")
`),
				},
			},
			expect: []string{"xfs"},
		},
		{
			name: `a seemingly vfs bug`,
			crashes: []*subsystem.Crash{
				{
					GuiltyPath: `fs/namei.c`,
				},
				{
					GuiltyPath: `fs/namei.c`,
					SyzRepro: []byte(`# https://syzkaller.appspot.com/bug?id=cdaf5ed409125df023889aefe50b4cc4a41c0973
# See https://goo.gl/kgGztJ for information about syzkaller reproducers.
#{"threaded":true,"repeat":true,"procs":6,"slowdown":1,"sandbox":"","sandbox_arg":0,"close_fds":false,"ieee802154":true,"sysctl":true,"tmpdir":true,"segv":true}
syz_mount_image$ntfs3(&(0x7f000001f740), &(0x7f000001f780)='./file0\x00', 0x0, &(0x7f0000000200)=ANY=[@ANYBLOB="64697363==")
mkdirat(0xffffffffffffff9c, &(0x7f0000000600)='./file0aaaaaaaaaaaaaaaaa\x00', 0x0)
symlinkat(&(0x7f00000004c0)='./file0aaaaaaaaaa/file0\x00', 0xffffffffffffff9c, &(0x7f0000000280)='./file0aaaaaa/file0\x00')
`),
				},
			},
			expect: []string{"ntfs3"},
		},
		{
			name: `a bug with page cache in guilty path`,
			crashes: []*subsystem.Crash{
				{
					GuiltyPath: `mm/filemap.c`,
				},
				{
					GuiltyPath: `mm/filemap.c`,
					SyzRepro: []byte(`# https://syzkaller.appspot.com/bug?id=cdaf5ed409125df023889aefe50b4cc4a41c0973
# See https://goo.gl/kgGztJ for information about syzkaller reproducers.
#{"threaded":true,"repeat":true,"procs":6,"slowdown":1,"sandbox":"","sandbox_arg":0,"close_fds":false,"ieee802154":true,"sysctl":true,"tmpdir":true,"segv":true}
syz_mount_image$ntfs3(&(0x7f000001f740), &(0x7f000001f780)='./file0\x00', 0x0, &(0x7f0000000200)=ANY=[@ANYBLOB="64697363==")
mkdirat(0xffffffffffffff9c, &(0x7f0000000600)='./file0aaaaaaaaaaaaaaaaa\x00', 0x0)
symlinkat(&(0x7f00000004c0)='./file0aaaaaaaaaa/file0\x00', 0xffffffffffffff9c, &(0x7f0000000280)='./file0aaaaaa/file0\x00')
`),
				},
			},
			// There should be no mm in the subsystems.
			expect: []string{"ntfs3"},
		},
		{
			name: "dri bug with usb call",
			crashes: []*subsystem.Crash{
				{
					GuiltyPath: `drivers/gpu/drm/udl/udl_drv.c`,
				},
				{
					GuiltyPath: `drivers/gpu/drm/udl/udl_drv.c`,
					SyzRepro: []byte(`
# https://syzkaller.appspot.com/bug?id=56e9aec9bc3b5378c9b231a3f4b3329cf9f80990
# See https://goo.gl/kgGztJ for information about syzkaller reproducers.
#{"procs":1,"slowdown":1,"sandbox":"none","sandbox_arg":0,"tun":true,"netdev":true,"close_fds":true}
syz_usb_connect(0x0, 0x24, &(0x7f0000000140)=ANY=[@ANYBLOB="12010000abbe6740e9174e8b089c000000010902120001000000000904000800ff"], 0x0)
`),
				},
			},
			expect: []string{"dri", "usb"},
		},
		{
			name: "ntfs bug with one ntfs guilty path",
			crashes: []*subsystem.Crash{
				{
					GuiltyPath: `mm/folio-compat.c`,
				},
				{
					GuiltyPath: `mm/folio-compat.c`,
				},
				{
					GuiltyPath: `mm/folio-compat.c`,
				},
				{
					// By chance just one was correct.
					GuiltyPath: `fs/ntfs3/frecord.c`,
					SyzRepro: []byte(`
# https://syzkaller.appspot.com/bug?id=9a239048a7fff1d8d9b276b240522a2293468dba
# See https://goo.gl/kgGztJ for information about syzkaller reproducers.
#{"procs":1,"slowdown":1,"sandbox":"","sandbox_arg":0,"close_fds":false}
syz_mount_image$ntfs3(&(0x7f000001f740), &(0x7f000001f780)='./file0\x00', 0x0, &(0x7f0000000200)=ANY=[@ANYBLOB="64697363==")
`),
				},
				{
					GuiltyPath: `mm/folio-compat.c`,
					SyzRepro: []byte(`
# https://syzkaller.appspot.com/bug?id=56e9aec9bc3b5378c9b231a3f4b3329cf9f80990
# See https://goo.gl/kgGztJ for information about syzkaller reproducers.
#{"procs":1,"slowdown":1,"sandbox":"none","sandbox_arg":0,"tun":true,"netdev":true,"close_fds":true}
syz_mount_image$ntfs3(&(0x7f000001f740), &(0x7f000001f780)='./file0\x00', 0x0, &(0x7f0000000200)=ANY=[@ANYBLOB="64697363==")
`),
				},
			},
			expect: []string{"ntfs3"},
		},
		{
			name: "many repros point to ntfs, all guilty files are wrong",
			crashes: []*subsystem.Crash{
				{
					GuiltyPath: `arch/arm64/kernel/stacktrace.c`,
				},
				{
					GuiltyPath: `arch/arm64/kernel/stacktrace.c`,
				},
				{
					GuiltyPath: `arch/arm64/kernel/stacktrace.c`,
				},
				{
					GuiltyPath: `arch/arm64/kernel/stacktrace.c`,
					SyzRepro: []byte(`
syz_mount_image$ntfs3(&(0x7f000001f740), &(0x7f000001f780)='./file0\x00', 0x0, &(0x7f0000000200)=ANY=[@ANYBLOB="64697363==")
`),
				},
				{
					GuiltyPath: `arch/arm64/kernel/stacktrace.c`,
					SyzRepro: []byte(`
syz_mount_image$ntfs3(&(0x7f000001f740), &(0x7f000001f780)='./file0\x00', 0x0, &(0x7f0000000200)=ANY=[@ANYBLOB="64697363==")
`),
				},
				{
					GuiltyPath: `arch/arm64/kernel/stacktrace.c`,
					SyzRepro: []byte(`
syz_mount_image$ntfs3(&(0x7f000001f740), &(0x7f000001f780)='./file0\x00', 0x0, &(0x7f0000000200)=ANY=[@ANYBLOB="64697363==")
`),
				},
			},
			// "arm" is just too omnipresent, we have to mention it.
			expect: []string{"ntfs3", "arm"},
		},
		{
			name: "guilty files point to media, many repros to usb",
			crashes: []*subsystem.Crash{
				{
					// Suppose, in one case report parsing failed.
					GuiltyPath: `arch/arm64/kernel/stacktrace.c`,
				},
				{
					GuiltyPath: `drivers/media/mc/mc-entity.c`,
				},
				{
					GuiltyPath: `drivers/media/mc/mc-entity.c`,
				},
				{
					GuiltyPath: `drivers/media/mc/mc-entity.c`,
				},
				{
					GuiltyPath: `drivers/media/mc/mc-entity.c`,
					SyzRepro: []byte(`
syz_usb_connect(0x0, 0x58, &(0x7f0000000100)=ANY=[@ANYBLOB="1201000036ee3808d30b55056"])
`),
				},
				{
					GuiltyPath: `drivers/media/mc/mc-entity.c`,
					SyzRepro: []byte(`
syz_usb_connect(0x0, 0x58, &(0x7f0000000100)=ANY=[@ANYBLOB="1201000036ee3808d30b55056"])
`),
				},
				{
					GuiltyPath: `drivers/media/mc/mc-entity.c`,
					SyzRepro: []byte(`
syz_usb_connect(0x0, 0x58, &(0x7f0000000100)=ANY=[@ANYBLOB="1201000036ee3808d30b55056"])
`),
				},
			},
			// "media" is picked because it's in >= 2/3 guilty paths.
			expect: []string{"media", "usb"},
		},
		{
			name: "wireless bug that should not be net",
			crashes: []*subsystem.Crash{
				{
					GuiltyPath: `net/mac80211/rate.c`,
				},
			},
			expect: []string{"wireless"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			names := []string{}
			for _, e := range group.Extract(test.crashes) {
				names = append(names, e.Name)
			}
			assert.ElementsMatch(t, names, test.expect, test.name)
		})
	}
}
