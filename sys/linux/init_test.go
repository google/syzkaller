// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package linux_test

import (
	"testing"

	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
	"github.com/google/syzkaller/sys/targets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNeutralize(t *testing.T) {
	prog.TestDeserializeHelper(t, targets.Linux, targets.AMD64, nil, []prog.DeserializeTest{
		{
			In:  `syslog(0x10000000006, 0x0, 0x0)`,
			Out: `syslog(0x9, 0x0, 0x0)`,
		},
		{
			In:  `syslog(0x10000000007, 0x0, 0x0)`,
			Out: `syslog(0x9, 0x0, 0x0)`,
		},
		{
			In: `syslog(0x1, 0x0, 0x0)`,
		},

		{
			In:  `ptrace(0xf000000000, 0x0)`,
			Out: `ptrace(0xffffffffffffffff, 0x0)`,
		},
		{
			In:  `ptrace$peek(0x0, 0x0, &(0x7f0000000000))`,
			Out: `ptrace$peek(0xffffffffffffffff, 0x0, &(0x7f0000000000))`,
		},
		{
			In: `ptrace(0x1, 0x0)`,
		},
		{
			In:  `arch_prctl$ARCH_SET_GS(0xf00000001002, 0x0)`,
			Out: `arch_prctl$ARCH_SET_GS(0x1001, 0x0)`,
		},
		{
			In: `arch_prctl$ARCH_SET_GS(0x1003, 0x0)`,
		},
		{
			In:  `ioctl(0x0, 0x200000c0045877, 0x0)`,
			Out: `ioctl(0x0, 0xc0045878, 0x0)`,
		},
		{
			In:  `fanotify_mark(0x1, 0x2, 0x407fe029, 0x3, 0x0)`,
			Out: `fanotify_mark(0x1, 0x2, 0x4078e029, 0x3, 0x0)`,
		},
		{
			In: `fanotify_mark(0xffffffffffffffff, 0xffffffffffffffff, 0xfffffffffff8ffff, 0xffffffffffffffff, 0x0)`,
		},
		{
			In:  `syz_init_net_socket$bt_hci(0x1, 0x0, 0x0)`,
			Out: `syz_init_net_socket$bt_hci(0xffffffffffffffff, 0x0, 0x0)`,
		},
		{
			In: `syz_init_net_socket$bt_hci(0x27, 0x0, 0x0)`,
		},
		{
			In: `syz_init_net_socket$bt_hci(0x1a, 0x0, 0x0)`,
		},
		{
			In: `syz_init_net_socket$bt_hci(0x1f, 0x0, 0x0)`,
		},
		{
			In: `syz_init_net_socket$qrtr(0x2a, 0x2, 0x0)`,
		},
		{
			In:  `mmap(0x0, 0x0, 0x0, 0x0, 0x0, 0x0)`,
			Out: `mmap(0x0, 0x0, 0x0, 0x10, 0x0, 0x0)`,
		},
		{
			In: `mremap(0x0, 0x0, 0x0, 0xcc, 0x0)`,
		},
		{
			In:  `mremap(0x0, 0x0, 0x0, 0xcd, 0x0)`,
			Out: `mremap(0x0, 0x0, 0x0, 0xcf, 0x0)`,
		},
		{
			In: `
mknod(0x0, 0x1000, 0x0)
mknod(0x0, 0x8000, 0x0)
mknod(0x0, 0xc000, 0x0)
mknod(0x0, 0x2000, 0x0)
mknod(0x0, 0x6000, 0x0)
mknod(0x0, 0x6000, 0x700)
`,
			Out: `
mknod(0x0, 0x1000, 0x0)
mknod(0x0, 0x8000, 0x0)
mknod(0x0, 0xc000, 0x0)
mknod(0x0, 0x8000, 0x0)
mknod(0x0, 0x8000, 0x0)
mknod(0x0, 0x6000, 0x700)
`,
		},
		{
			In: `
exit(0x3)
exit(0x43)
exit(0xc3)
exit(0xc3)
exit_group(0x5a)
exit_group(0x43)
exit_group(0x443)
`,
			Out: `
exit(0x3)
exit(0x1)
exit(0x1)
exit(0x1)
exit_group(0x5a)
exit_group(0x1)
exit_group(0x1)
`,
		},
		{
			In: `
syz_open_dev$tty1(0xc, 0x4, 0x4)
syz_open_dev$tty1(0xb, 0x2, 0x4)
syz_open_dev$tty1(0xc, 0x4, 0x5)
`,
			Out: `
syz_open_dev$tty1(0xc, 0x4, 0x4)
syz_open_dev$tty1(0xc, 0x4, 0x4)
syz_open_dev$tty1(0xc, 0x4, 0x1)
`,
		},
		{
			In:  `sched_setattr(0x0, &(0x7f00000002c0)={0x0, 0x1, 0x0, 0x0, 0x3, 0x0, 0x0, 0x0, 0x0, 0x0}, 0x0)`,
			Out: `sched_setattr(0x0, &(0x7f00000002c0)={0x0, 0x0, 0x0, 0x0, 0x3}, 0x0)`,
		},
		{
			In:  `sched_setattr(0x0, &(0x7f00000002c0)={0x0, 0x2, 0x0, 0x0, 0x3, 0x0, 0x0, 0x0, 0x0, 0x0}, 0x0)`,
			Out: `sched_setattr(0x0, &(0x7f00000002c0)={0x0, 0x0, 0x0, 0x0, 0x3}, 0x0)`,
		},
		{
			In:  `sched_setattr(0x0, &(0x7f00000002c0)={0x0, 0x3, 0x0, 0x0, 0x3, 0x0, 0x0, 0x0, 0x0, 0x0}, 0x0)`,
			Out: `sched_setattr(0x0, &(0x7f00000002c0)={0x0, 0x3, 0x0, 0x0, 0x3}, 0x0)`,
		},
		{
			In:  `sched_setattr(0x0, 0x123456, 0x0)`,
			Out: `sched_setattr(0x0, 0x0, 0x0)`,
		},
		{
			In:        `sched_setattr(0x0, &(0x7f00000001c0)=ANY=[@ANYBLOB="1234567812345678"], 0x0)`,
			Out:       `sched_setattr(0x0, &(0x7f00000001c0)={0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0}, 0x0)`,
			StrictErr: `wrong array arg`,
		},
		{
			In:  `openat(0xffffffffffffff9c, &(0x7f0000000100)='./sys/bus/platform/drivers/bxt_wcove_usbc/bind\x00', 0x1, 0x0)`,
			Out: `openat(0xffffffffffffff9c, &(0x7f0000000100)='./file0\x00', 0x1, 0x0)`,
		},
		{
			In:  `openat$sysfs(0xffffffffffffff9c, &(0x7f0000000100)='/sys/bus/pci/drivers_probe\x00', 0x1, 0x0)`,
			Out: `openat$sysfs(0xffffffffffffff9c, &(0x7f0000000100)='./file0\x00', 0x1, 0x0)`,
		},
		{
			In: `openat(0xffffffffffffff9c, &(0x7f0000000100)='./sys/bus/platform/drivers/foo/uevent\x00', 0x1, 0x0)`,
		},
		{
			// Non-ASCII bytes in the path must not confuse the matching.
			In: `openat(0xffffffffffffff9c, ` +
				`&(0x7f0000000100)='./sys/bus/pci/drivers/CAF\xc3\x89 NAND/bind\x00', 0x1, 0x0)`,
			Out: `openat(0xffffffffffffff9c, &(0x7f0000000100)='./file0\x00', 0x1, 0x0)`,
		},
		{
			// The directory and the attribute may be opened in separate calls.
			In: `
r0 = openat$dir(0xffffffffffffff9c, &(0x7f0000000040)='./sys/bus/pci/drivers/e1000\x00', 0x0, 0x0)
openat(r0, &(0x7f0000000080)='bind\x00', 0x1, 0x0)
`,
			Out: `
r0 = openat$dir(0xffffffffffffff9c, &(0x7f0000000040)='./sys/bus/pci/drivers/e1000\x00', 0x0, 0x0)
openat(r0, &(0x7f0000000080)='./fi\x00', 0x1, 0x0)
`,
		},
		{
			// Embedded NUL byte with trailing garbage must still be caught.
			In: `openat(0xffffffffffffff9c, &(0x7f0000000100)=` +
				`"2e2f7379732f6275732f7063692f647269766572735f70726f6265006761726261676500", 0x1, 0x0)`,
			Out: `openat(0xffffffffffffff9c, &(0x7f0000000100)='./file0\x00', 0x1, 0x0)`,
		},
		{
			// The replacement must not grow the buffer (it would not fit into the data region here).
			In:  `openat(0xffffffffffffff9c, &(0x7f0000fffffb)='bind\x00', 0x1, 0x0)`,
			Out: `openat(0xffffffffffffff9c, &(0x7f0000fffffb)='./fi\x00', 0x1, 0x0)`,
		},
		{
			// One case per syscall to verify the path argument indices.
			In:  `open(&(0x7f0000000040)='./sys/bus/pci/drivers/e1000/bind\x00', 0x2, 0x0)`,
			Out: `open(&(0x7f0000000040)='./file0\x00', 0x2, 0x0)`,
		},
		{
			In: `openat2(0xffffffffffffff9c, &(0x7f0000000040)='./sys/bus/pci/drivers/e1000/unbind\x00', ` +
				`&(0x7f0000000080)={0x2, 0x0, 0x0}, 0x18)`,
			Out: `openat2(0xffffffffffffff9c, &(0x7f0000000040)='./file0\x00', &(0x7f0000000080)={0x2}, 0x18)`,
		},
		{
			In:  `chdir(&(0x7f0000000040)='./sys/bus/pci/drivers/e1000/foo/../bind/\x00')`,
			Out: `chdir(&(0x7f0000000040)='./file0\x00')`,
		},
		{
			In: `mount$bind(&(0x7f0000000040)='./sys/bus/pci/drivers/e1000/bind\x00', ` +
				`&(0x7f0000000080)='./file1\x00', 0x0, 0x1000, 0x0)`,
			Out: `mount$bind(&(0x7f0000000040)='./file0\x00', ` +
				`&(0x7f0000000080)='./file1\x00', 0x0, 0x1000, 0x0)`,
		},
		{
			In:  `open_tree(0xffffffffffffff9c, &(0x7f0000000040)='./sys/bus/pci/drivers/e1000/remove_id\x00', 0x1)`,
			Out: `open_tree(0xffffffffffffff9c, &(0x7f0000000040)='./file0\x00', 0x1)`,
		},
		{
			In: `open_tree_attr$auto(0xffffffffffffff9c, ` +
				`&(0x7f0000000040)='./sys/bus/pci/drivers/e1000/bind\x00', 0x1, 0x0, 0x0)`,
			Out: `open_tree_attr$auto(0xffffffffffffff9c, &(0x7f0000000040)='./file0\x00', 0x1, 0x0, 0x0)`,
		},
		{
			In: `name_to_handle_at(0xffffffffffffff9c, ` +
				`&(0x7f0000000040)='./sys/bus/pci/drivers/e1000/bind\x00', 0x0, 0x0, 0x0)`,
			Out: `name_to_handle_at(0xffffffffffffff9c, &(0x7f0000000040)='./file0\x00', 0x0, 0x0, 0x0)`,
		},
		{
			In:  `symlink(&(0x7f0000000100)='./sys/bus/platform/drivers/foo/unbind\x00', &(0x7f0000000200)='./link0\x00')`,
			Out: `symlink(&(0x7f0000000100)='./file0\x00', &(0x7f0000000200)='./link0\x00')`,
		},
		{
			In: `symlinkat(&(0x7f0000000040)='./sys/bus/pci/drivers/e1000/bind\x00', ` +
				`0xffffffffffffff9c, &(0x7f0000000080)='./unbind\x00')`,
			Out: `symlinkat(&(0x7f0000000040)='./file0\x00', ` +
				`0xffffffffffffff9c, &(0x7f0000000080)='./file0\x00')`,
		},
		{
			In: `linkat(0xffffffffffffff9c, &(0x7f0000000040)='./bind\x00', ` +
				`0xffffffffffffff9c, &(0x7f0000000080)='./new_id\x00', 0x0)`,
			Out: `linkat(0xffffffffffffff9c, &(0x7f0000000040)='./file\x00', ` +
				`0xffffffffffffff9c, &(0x7f0000000080)='./file0\x00', 0x0)`,
		},
		{
			In: `move_mount(0xffffffffffffff9c, &(0x7f0000000040)='./sys/bus/pci/drivers/e1000/unbind\x00', ` +
				`0xffffffffffffff9c, &(0x7f0000000080)='./file1\x00', 0x0)`,
			Out: `move_mount(0xffffffffffffff9c, &(0x7f0000000040)='./file0\x00', ` +
				`0xffffffffffffff9c, &(0x7f0000000080)='./file1\x00', 0x0)`,
		},
		{
			// Mount data (arg 4) must not be treated as a path even if it contains 'bind'.
			In: `mount(0x0, &(0x7f0000000040)='./file0\x00', &(0x7f0000000080)='tmpfs\x00', 0x0, &(0x7f00000000c0)='bind\x00')`,
		},
		{
			In: `
openat(0xffffffffffffff9c, &(0x7f0000000000)='./sys/devices/pci0000:00/0000:00:02.0/resource0\x00', 0x2, 0x0)
openat(0xffffffffffffff9c, &(0x7f0000000100)='./sys/bus/pci/devices/0000:00:02.0/config\x00', 0x2, 0x0)
openat(0xffffffffffffff9c, &(0x7f0000000200)='./proc/bus/pci/00/02.0\x00', 0x2, 0x0)
openat(0xffffffffffffff9c, &(0x7f0000000300)='./sys/bus/pci/slots/3/power\x00', 0x1, 0x0)
`,
			Out: `
openat(0xffffffffffffff9c, &(0x7f0000000000)='./file0\x00', 0x2, 0x0)
openat(0xffffffffffffff9c, &(0x7f0000000100)='./file0\x00', 0x2, 0x0)
openat(0xffffffffffffff9c, &(0x7f0000000200)='./file0\x00', 0x2, 0x0)
openat(0xffffffffffffff9c, &(0x7f0000000300)='./file0\x00', 0x1, 0x0)
`,
		},
		{
			// PCI attribute names are fine outside of PCI device directories.
			In: `
mkdirat(0xffffffffffffff9c, &(0x7f0000000000)='./config\x00', 0x1ff)
mount(0x0, &(0x7f0000000000)='./config\x00', &(0x7f0000000040)='configfs\x00', 0x0, 0x0)
mkdirat(0xffffffffffffff9c, &(0x7f0000000080)='./config/usb_gadget/g1\x00', 0x1ff)
r0 = openat$dir(0xffffffffffffff9c, &(0x7f0000000100)='./sys/block/zram0\x00', 0x0, 0x0)
openat(r0, &(0x7f0000000140)='reset\x00', 0x1, 0x0)
openat(0xffffffffffffff9c, &(0x7f0000000180)='./sys/block/zram0/reset\x00', 0x1, 0x0)
`,
		},
		{
			// Programs must not get hold of a PCI device directory (directly or as the parent
			// of a child device), otherwise its attributes could be opened via paths that
			// do not look like PCI ones.
			In: `
openat$dir(0xffffffffffffff9c, &(0x7f0000000000)='./sys/devices/pci0000:00/0000:00:02.0\x00', 0x0, 0x0)
mount$bind(&(0x7f0000000100)='./file3/0000:00:03.0/\x00', &(0x7f0000000200)='./file1\x00', 0x0, 0x1000, 0x0)
symlink(&(0x7f0000000300)='./sys/bus/pci/devices/0000:00:02.0/.\x00', &(0x7f0000000400)='./file2\x00')
chdir(&(0x7f0000000500)='./sys/bus/virtio/devices/virtio0/..\x00')
chroot(&(0x7f0000000700)='./sys/devices/pci0000:00/0000:00:02.0\x00')
chdir(&(0x7f0000000600)='./sys/devices/pci0000:00\x00')
`,
			Out: `
openat$dir(0xffffffffffffff9c, &(0x7f0000000000)='./file0\x00', 0x0, 0x0)
mount$bind(&(0x7f0000000100)='./file0\x00', &(0x7f0000000200)='./file1\x00', 0x0, 0x1000, 0x0)
symlink(&(0x7f0000000300)='./file0\x00', &(0x7f0000000400)='./file2\x00')
chdir(&(0x7f0000000500)='./file0\x00')
chroot(&(0x7f0000000700)='./file0\x00')
chdir(&(0x7f0000000600)='./sys/devices/pci0000:00\x00')
`,
		},
		{
			In: `
r0 = openat(0xffffffffffffff9c, &(0x7f0000000040)='./sys/bus/usb/drivers/cdc_ether/new_id\x00', 0x1, 0x0)
write(r0, &(0x7f0000000080)='0424 9514\x00', 0xa)
`,
			Out: `
r0 = openat(0xffffffffffffff9c, &(0x7f0000000040)='./file0\x00', 0x1, 0x0)
write(r0, &(0x7f0000000080)='0424 9514\x00', 0xa)
`,
		},
		{
			In: `ioctl$DM_DEV_SUSPEND(0xffffffffffffffff, 0xc138fd06, &(0x7f0000000000)=` +
				`{0x4, 0x0, 0x0, 0x138, 0x138, 0x0, 0x0, 0x3, 0x0, 0x0, @by_name={0x0, {'syz', 0x0, '0\x00'}}, ""})`,
			Out: `ioctl$DM_DEV_SUSPEND(0xffffffffffffffff, 0xc138fd06, &(0x7f0000000000)=` +
				`{0x4, 0x0, 0x0, 0x138, 0x138, 0x0, 0x0, 0x1, 0x0, 0x0, @by_name={0x0, {'syz', 0x0, '0\x00'}}})`,
		},
		{
			In:  `openat$dm_dev(0xffffffffffffff9c, &(0x7f0000000000)='./dm0\x00', 0x42, 0x0)`,
			Out: `openat$dm_dev(0xffffffffffffff9c, &(0x7f0000000000)='./dm0\x00', 0x2, 0x0)`,
		},
		{
			In:  `openat$md(0xffffffffffffff9c, &(0x7f0000000000)={'/dev/md', @num=0x0, 0x0}, 0x42, 0x0)`,
			Out: `openat$md(0xffffffffffffff9c, &(0x7f0000000000)={'/dev/md', @num=0x0, 0x0}, 0x2, 0x0)`,
		},
		{
			In:  `openat$md_node(0xffffffffffffff9c, &(0x7f0000000000)='./md0\x00', 0x42, 0x0)`,
			Out: `openat$md_node(0xffffffffffffff9c, &(0x7f0000000000)='./md0\x00', 0x2, 0x0)`,
		},
		{
			In:  `ioctl$ADD_NEW_DISK(0xffffffffffffffff, 0x40140921, &(0x7f0000000000)={0x0, {0x8, 0x0}, 0x0, 0x6})`,
			Out: `ioctl$ADD_NEW_DISK(0xffffffffffffffff, 0x40140921, &(0x7f0000000000)={0x0, {0x1, 0x0}, 0x0, 0x6})`,
		},
		{
			In: `ioctl$EXT4_IOC_SET_TUNE_SB_PARAM(0xffffffffffffffff, 0x40e8662e, &(0x7f0000000000)=` +
				`{0x1, 0x0, 0x3, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,` +
				` 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, '\x00', '\x00'})`,
			Out: `ioctl$EXT4_IOC_SET_TUNE_SB_PARAM(0xffffffffffffffff, 0x40e8662e, &(0x7f0000000000)=` +
				`{0x1, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,` +
				` 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, '\x00', '\x00'})`,
		},
		{
			In: `ioctl$EXT4_IOC_SET_TUNE_SB_PARAM(0xffffffffffffffff, 0x40e8662e, &(0x7f0000000000)=` +
				`{0x1, 0x0, 0x2, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,` +
				` 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, '\x00', '\x00'})`,
		},
		{
			In: `ioctl$EXT4_IOC_SET_TUNE_SB_PARAM(0xffffffffffffffff, 0x40e8662e, &(0x7f0000000000)=` +
				`{0x1000, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,` +
				` 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 'errors=panic\x00', '\x00'})`,
			Out: `ioctl$EXT4_IOC_SET_TUNE_SB_PARAM(0xffffffffffffffff, 0x40e8662e, &(0x7f0000000000)=` +
				`{0x1000, 0x0, 0x1, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,` +
				` 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, '\x00', '\x00'})`,
			StrictErr: `bad string value`,
		},
		{
			In: `ioctl$EXT4_IOC_SET_TUNE_SB_PARAM(0xffffffffffffffff, 0x40e8662e,` +
				` &(0x7f0000000000)=ANY=[@ANYBLOB='errors=panic\x00'])`,
			Out: `ioctl$EXT4_IOC_SET_TUNE_SB_PARAM(0xffffffffffffffff, 0x40e8662e, &(0x7f0000000000)=` +
				`{0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0,` +
				` 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, '\x00', '\x00'})`,
			StrictErr: `wrong array arg`,
		},
		{
			In:  `ioctl$EXT4_IOC_SET_TUNE_SB_PARAM(0xffffffffffffffff, 0x40e8662e, 0x123456)`,
			Out: `ioctl$EXT4_IOC_SET_TUNE_SB_PARAM(0xffffffffffffffff, 0x40e8662e, 0x0)`,
		},
		{
			In:  `ioctl(0xffffffffffffffff, 0x40e8662e, &(0x7f0000000000)='errors=panic\x00')`,
			Out: `ioctl(0xffffffffffffffff, 0x80e8662d, &(0x7f0000000000)='errors=panic\x00')`,
		},
	})
}

func TestDeserializeStrictUnsafe(t *testing.T) {
	t.Parallel()
	target, _ := prog.GetTarget("linux", "amd64")
	// Raw mode must preserve the global file name, allow to use mmap with non-fixed addr,
	// and allow to use disabled syscalls.
	had := `openat(0x0, &(0x7f0000000000)='/dev/foo', 0x0, 0x0)
mmap(0x0, 0x0, 0x0, 0x0, 0x0, 0x0)
clone(0x0, &(0x7f0000000000), &(0x7f0000000010), &(0x7f0000000020), &(0x7f0000000030))
`
	p, err := target.Deserialize([]byte(had), prog.StrictUnsafe)
	if err != nil {
		t.Fatal(err)
	}
	got := string(p.Serialize())
	if had != got {
		t.Fatalf("program was changed:\n%s\ngot:\n%s", had, got)
	}
}

func TestDeserializeNonStrictUnsafe(t *testing.T) {
	t.Parallel()
	target, _ := prog.GetTarget("linux", "amd64")
	_, err := target.Deserialize([]byte("clone()"), prog.NonStrictUnsafe)
	if err != nil {
		t.Fatal(err)
	}
}

func TestAllowFilePath(t *testing.T) {
	t.Parallel()
	target, err := prog.GetTarget(targets.Linux, targets.AMD64)
	require.NoError(t, err)
	require.NotNil(t, target.AllowFilePath)

	for _, p := range []string{
		"",
		"/sys/bus/pci/drivers_probe",
		"/sys/bus/pci/drivers_probe\x00trailing",
		"/sys/bus/pci/drivers/e1000/bind",
		"/sys/bus/pci/drivers/e1000/bind/",
		"/sys/bus/pci/drivers/e1000/foo/../unbind",
		"/sys/bus/pci/drivers/e1000/new_id",
		"/sys/bus/pci/drivers/e1000/remove_id",
		"/sys/devices/platform/pcspkr/driver_override",
		"bind",
		"/proc/bus/pci/00",
		"/proc/bus/pci/00/00.0",
		"/proc/bus/pci/0000:00/1f.7",
		"/proc/bus/pci/00010000:ff/00.0",
		"../bus/pci/00/00.0",
		"00.0",
		"/sys/devices/pci0000:00/0000:00:02.0/resource0",
		"/sys/devices/pci0000:00/0000:00:02.0/resource0_wc",
		"/sys/devices/pci0000:00/0000:00:02.0/resource13_resize",
		"/sys/devices/pci0000:00/0000:00:02.0/rom",
		"/sys/class/pci_bus/0000:00/legacy_io",
		"/sys/class/pci_bus/0000:00/legacy_mem_sparse",
		"/sys/devices/pci0000:00/0000:00:02.0/config",
		"/sys/bus/pci/devices/0000:00:02.0/config",
		"/sys/class/wakeup/wakeup0/device/config",
		"/sys/bus/virtio/devices/virtio0/../config",
		"/sys/devices/pci0000:00/0000:00:01.0/remove",
		"/sys/devices/pci0000:00/0000:00:01.0/reset",
		"/sys/devices/pci0000:00/0000:00:01.0/reset_subordinate",
		"/sys/class/net/eth0/device/remove",
		"reset_subordinate",
		"/sys/bus/pci/slots/3/power",
		"/config",
		"../reset",
	} {
		assert.False(t, target.AllowFilePath(p), "path: %q", p)
	}
	for _, p := range []string{
		"/sys/bus/pci/rescan",
		"/sys/bus/pci/devices",
		"/sys/bus/pci/drivers/CAFÉ NAND/uevent",
		"/sys/bus/platform/drivers/foo/uevent",
		"/proc/bus/pci/devices",
		"/sys/devices/pci0000:00/0000:00:01.0/resource",
		"/sys/devices/pci0000:00/0000:00:01.0/enable",
		"/sys/devices/pci0000:00/0000:00:01.0/msi_bus",
		"/sys/devices/pci0000:00/0000:00:01.0/d3cold_allowed",
		"/sys/devices/pci0000:00/0000:00:01.0/reset_method",
		"/sys/devices/pci0000:00/0000:00:01.0/power/control",
		"/sys/devices/virtual/bluetooth/hci1/power",
		"/sys/devices/pci0000:00/0000:00:04.0/usb1/1-1/remove",
		"/sys/devices/pnp0/00:05/resources",
		"/sys/block/zram0/reset",
		"/sys/kernel/config",
		"/sys/devices/ap/card00/config",
		"/proc/net/vlan/config",
		"/proc/self/net/vlan/config",
		"config",
		"reset",
	} {
		assert.True(t, target.AllowFilePath(p), "path: %q", p)
	}

	// Check the fixed paths in the descriptions, including the ones nested in structs.
	for _, sc := range target.Syscalls {
		argIdx := -1
		prefix := ""
		switch sc.CallName {
		case "open", "creat", "chdir", "syz_open_dev":
			argIdx = 0
		case "openat", "openat2", "open_tree", "open_tree_attr", "name_to_handle_at":
			argIdx = 1
		case "syz_open_procfs":
			argIdx = 1
			prefix = "/proc/self/"
		}
		if argIdx < 0 || len(sc.Args) <= argIdx {
			continue
		}
		prog.ForeachArgType(sc.Args[argIdx].Type, func(typ prog.Type, ctx *prog.TypeCtx) {
			bufType, ok := typ.(*prog.BufferType)
			if !ok || bufType.Kind != prog.BufferString {
				return
			}
			for _, rawVal := range bufType.Values {
				assert.True(t, target.AllowFilePath(prefix+rawVal),
					"syscall %s exposes forbidden path %q", sc.Name, rawVal)
			}
		})
	}
}
