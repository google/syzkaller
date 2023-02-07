// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"testing"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/stretchr/testify/assert"
)

func TestFsSubsystemFlow(t *testing.T) {
	// Test that we can do the following:
	// 1. Delay the reporting of possible vfs bugs until we have found a reproducer.
	// 2. Once the reproducer comes, extract the extra subsystems and report it.

	c := NewCtx(t)
	defer c.Close()

	client := c.makeClient(clientPublicFs, keyPublicFs, true)
	build := testBuild(1)
	client.UploadBuild(build)

	// A. Make sure non-fs bugs are not affected.
	// -----------------------------------------

	crash := testCrash(build, 1)
	crash.Title = "WARNING: abcd"
	crash.Log = []byte("log log log")
	crash.GuiltyFiles = []string{"kernel/kernel.c"}
	crash.Maintainers = []string{"maintainer@kernel.org"}
	client.ReportCrash(crash)

	// We skip the first stage and report the bug right away.
	reply := c.pollEmailBug()
	c.expectEQ(reply.Subject, "[syzbot] [kernel?] WARNING: abcd")

	// B. Send a non-vfs bug without a reproducer.
	// -----------------------------------------

	crash = testCrash(build, 2)
	crash.Title = "WARNING in nilfs_dat_commit_end"
	crash.GuiltyFiles = []string{"fs/nilfs2/dat.c"}
	crash.Log = []byte("log log log")
	crash.Maintainers = []string{"maintainer@kernel.org"}
	client.ReportCrash(crash)

	reply = c.pollEmailBug()
	// The subsystem should have been taken from the guilty path.
	c.expectEQ(reply.Subject, "[syzbot] [nilfs?] WARNING in nilfs_dat_commit_end")
	assert.ElementsMatch(t, reply.To, []string{
		"konishi.ryusuke@gmail.com",
		"linux-fsdevel@vger.kernel.org",
		"linux-kernel@vger.kernel.org",
		"linux-nilfs@vger.kernel.org",
		"maintainer@kernel.org",
		"test@syzkaller.com",
	})

	// C. Send a possibly vfs bug without a reproducer.
	// -----------------------------------------

	crash = testCrash(build, 3)
	crash.Title = "WARNING in do_mkdirat"
	crash.GuiltyFiles = []string{"fs/namei.c"}
	crash.Log = []byte("log log log")
	crash.Maintainers = []string{"maintainer@kernel.org"}
	client.ReportCrash(crash)

	// As there's no other information, the bug is left at the first reporting.
	c.client.pollNotifs(0)
	vfsBug := client.pollBug()

	// D. Now report a reproducer for the (C) bug that does image mounting.
	// -----------------------------------------

	crash = testCrash(build, 4)
	crash.Title = "WARNING in do_mkdirat"
	crash.GuiltyFiles = []string{"fs/namei.c"}
	crash.Log = []byte("log log log")
	// nolint: lll
	crash.ReproSyz = []byte(`syz_mount_image$ntfs3(&(0x7f0000000240), &(0x7f000001f3c0)='./file0\x00', 0xc40, &(0x7f00000005c0)=ANY=[@ANYBLOB="0032"], 0x3, 0x1f398, &(0x7f000003e7c0)="111")
r0 = openat(0xffffffffffffff9c, &(0x7f0000000040)='.\x00', 0x0, 0x0)
mkdirat(r0, &(0x7f0000000180)='./bus\x00', 0x0)
mkdirat(r0, &(0x7f0000000280)='./bus/file0\x00', 0x0)
renameat2(r0, &(0x7f00000004c0)='./file0\x00', r0, &(0x7f0000000500)='./bus/file0/file0\x00', 0x0)`)
	crash.Maintainers = []string{"maintainer@kernel.org"}
	client.ReportCrash(crash)

	// Check that we're ready for upstreaming.
	c.client.pollNotifs(1)
	client.updateBug(vfsBug.ID, dashapi.BugStatusUpstream, "")
	// .. and poll the email.
	reply = c.pollEmailBug()
	c.expectEQ(reply.Subject, "[syzbot] [ntfs3?] WARNING in do_mkdirat")
	// Make sure ntfs3 maintainers are in the recipients.
	assert.ElementsMatch(t, reply.To, []string{
		"almaz.alexandrovich@paragon-software.com",
		"linux-fsdevel@vger.kernel.org",
		"linux-kernel@vger.kernel.org",
		"maintainer@kernel.org",
		"ntfs3@lists.linux.dev",
		"test@syzkaller.com",
	})
}

func TestVfsSubsystemFlow(t *testing.T) {
	// Test that we can do the following:
	// 1. Delay the reporting of possible vfs bugs until we have found a reproducer.
	// 2. Once the reproducer comes, extract the extra subsystems and report it.

	c := NewCtx(t)
	defer c.Close()

	client := c.makeClient(clientPublicFs, keyPublicFs, true)
	build := testBuild(1)
	client.UploadBuild(build)

	// A. Send a possibly vfs bug without a reproducer.
	// -----------------------------------------

	crash := testCrash(build, 1)
	crash.Title = "WARNING in do_mkdirat2"
	crash.GuiltyFiles = []string{"fs/namei.c"}
	crash.Log = []byte("log log log")
	crash.Maintainers = []string{"maintainer@kernel.org"}
	client.ReportCrash(crash)

	// As there's no other information, the bug is left at the first reporting.
	c.client.pollNotifs(0)
	vfsBug := client.pollBug()

	// B. Now report a reproducer for the (C) bug that does NO image mounting.
	// -----------------------------------------

	crash = testCrash(build, 2)
	crash.Title = "WARNING in do_mkdirat2"
	crash.GuiltyFiles = []string{"fs/namei.c"}
	crash.Log = []byte("log log log")
	crash.ReproSyz = []byte(`r0 = openat(0xffffffffffffff9c, &(0x7f0000000040)='.\x00', 0x0, 0x0)
mkdirat(r0, &(0x7f0000000180)='./bus\x00', 0x0)
mkdirat(r0, &(0x7f0000000280)='./bus/file0\x00', 0x0)
renameat2(r0, &(0x7f00000004c0)='./file0\x00', r0, &(0x7f0000000500)='./bus/file0/file0\x00', 0x0)`)
	crash.Maintainers = []string{"maintainer@kernel.org"}
	client.ReportCrash(crash)

	// Check that we're ready for upstreaming.
	c.client.pollNotifs(1)
	client.updateBug(vfsBug.ID, dashapi.BugStatusUpstream, "")
	// .. and poll the email.
	reply := c.pollEmailBug()
	c.expectEQ(reply.Subject, "[syzbot] [fs?] WARNING in do_mkdirat2")
}
