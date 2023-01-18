// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package legacy

func LinuxGetMaintainers(subsystemName string) []string {
	return linuxSubsystems[subsystemName].cc
}

type linuxSubsystemInfo struct {
	path string
	cc   []string
}

// These are taken from Linux v6.1. There will be no need to store them here once we
// begin to automatically parse the MAINTAINERS file.

// nolint:lll
var linuxSubsystems = map[string]linuxSubsystemInfo{
	"adfs":     {path: "fs/adfs/", cc: []string{}},
	"affs":     {path: "fs/affs/", cc: []string{"linux-fsdevel@vger.kernel.org", "dsterba@suse.com"}},
	"befs":     {path: "fs/befs/", cc: []string{"luisbg@kernel.org", "salah.triki@gmail.com"}},
	"bfs":      {path: "fs/bfs/", cc: []string{"aivazian.tigran@gmail.com"}},
	"btrfs":    {path: "fs/btrfs/", cc: []string{"josef@toxicpanda.com", "dsterba@suse.com", "linux-btrfs@vger.kernel.org", "clm@fb.com"}},
	"cramfs":   {path: "fs/cramfs/", cc: []string{"nico@fluxnic.net"}},
	"efs":      {path: "fs/efs/", cc: []string{}},
	"erofs":    {path: "fs/erofs/", cc: []string{"xiang@kernel.org", "chao@kernel.org", "linux-erofs@lists.ozlabs.org"}},
	"exfat":    {path: "fs/exfat/", cc: []string{"linkinjeon@kernel.org", "sj1557.seo@samsung.com", "linux-fsdevel@vger.kernel.org"}},
	"fat":      {path: "fs/fat/", cc: []string{"hirofumi@mail.parknet.co.jp"}},
	"ext4":     {path: "fs/ext4/", cc: []string{"linux-ext4@vger.kernel.org", "tytso@mit.edu", "adilger.kernel@dilger.ca"}},
	"f2fs":     {path: "fs/f2fs/", cc: []string{"linux-f2fs-devel@lists.sourceforge.net", "jaegeuk@kernel.org", "chao@kernel.org"}},
	"gfs2":     {path: "fs/gfs2/", cc: []string{"cluster-devel@redhat.com", "rpeterso@redhat.com", "agruenba@redhat.com"}},
	"hfs":      {path: "fs/hfs/", cc: []string{"linux-fsdevel@vger.kernel.org"}},
	"hfsplus":  {path: "fs/hfsplus/", cc: []string{"linux-fsdevel@vger.kernel.org"}},
	"hpfs":     {path: "fs/hpfs/", cc: []string{"mikulas@artax.karlin.mff.cuni.cz"}},
	"iso9660":  {path: "fs/isofs/", cc: []string{}},
	"jffs2":    {path: "fs/jffs2/", cc: []string{"linux-mtd@lists.infradead.org", "dwmw2@infradead.org", "richard@nod.at"}},
	"jfs":      {path: "fs/jfs/", cc: []string{"jfs-discussion@lists.sourceforge.net", "shaggy@kernel.org"}},
	"minix":    {path: "fs/minix/", cc: []string{}},
	"nilfs2":   {path: "fs/nilfs2/", cc: []string{"linux-nilfs@vger.kernel.org", "konishi.ryusuke@gmail.com"}},
	"ntfs":     {path: "fs/ntfs/", cc: []string{"linux-ntfs-dev@lists.sourceforge.net", "anton@tuxera.com"}},
	"ntfs3":    {path: "fs/ntfs3/", cc: []string{"ntfs3@lists.linux.dev", "almaz.alexandrovich@paragon-software.com"}},
	"ocfs2":    {path: "fs/ocfs2/", cc: []string{"ocfs2-devel@oss.oracle.com", "mark@fasheh.com", "jlbec@evilplan.org", "joseph.qi@linux.alibaba.com"}},
	"omfs":     {path: "fs/omfs/", cc: []string{"linux-karma-devel@lists.sourceforge.net", "me@bobcopeland.com"}},
	"qnx4":     {path: "fs/qnx4/", cc: []string{"al@alarsen.net"}},
	"qnx6":     {path: "fs/qnx6/", cc: []string{}},
	"reiserfs": {path: "fs/reiserfs/", cc: []string{"reiserfs-devel@vger.kernel.org"}},
	"romfs":    {path: "fs/romfs/", cc: []string{}},
	"squashfs": {path: "fs/squashfs/", cc: []string{"phillip@squashfs.org.uk", "squashfs-devel@lists.sourceforge.net"}},
	"sysv":     {path: "fs/sysv/", cc: []string{"hch@infradead.org"}},
	"tmpfs":    {path: "mm/shmem.c", cc: []string{"linux-mm@kvack.org", "akpm@linux-foundation.org", "hughd@google.com"}},
	"ubifs":    {path: "fs/ubifs/", cc: []string{"linux-mtd@lists.infradead.org", "richard@nod.at"}},
	"udf":      {path: "fs/udf/", cc: []string{"jack@suse.com"}},
	"ufs":      {path: "fs/ufs/", cc: []string{"dushistov@mail.ru"}},
	"vxfs":     {path: "fs/freevxfs/", cc: []string{"hch@infradead.org"}},
	"xfs":      {path: "fs/xfs/", cc: []string{"linux-xfs@vger.kernel.org", "djwong@kernel.org"}},
	"zonefs":   {path: "fs/zonefs/", cc: []string{"linux-fsdevel@vger.kernel.org", "damien.lemoal@opensource.wdc.com", "naohiro.aota@wdc.com"}}}
