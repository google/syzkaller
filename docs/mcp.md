# syz-agent in MCP mode

Example use with Gemini CLI:

1. Run `make agent`.

2. Create `mcp.config` file, for example:

```
{
	"http": "localhost:59999",
	"mcp": true,
	"syzkaller_repo": "git@github.com:syzkaller/syzkaller.git",
	"target": "linux/amd64",
	"image": "/buildroot_amd64-2022.11.clean",
	"kernel_config": "upstream-apparmor-kasan.config",
	"type": "qemu",
	"vm": {
		"count": 10,
		"cpu": 2,
		"mem": 2048,
		"cmdline": "root=/dev/sda1"
	},
	"cache_size": 107374182400
}
```

3. Start `syz-agent`:

```
bin/syz-agent -config mcp.config
```

4. Add the following to `~/.gemini/settings.json`:

```
{
	"mcpServers": {
		"syzkaller": {
			"httpUrl": "http://127.0.0.1:59999",
			"trust": true
		}
	}
}
```

5. Start Gemini CLI:

```
gemini
```

6. Test that `gemini` has connected to `syz-agent` by executing `/mcp` or `/mcp schema`.

7. Try the following prompt:

```
You are an experienced Linux kernel developer tasked with debugging a kernel crash root cause.
You need to provide a detailed explanation of the root cause for another developer to be
able to write a fix for the bug based on your explanation.

You must first run the following tools in the following order to prepare the environment:
 * base-commit-picker
 * kernel-checkouter
 * kernel-builder
 * codesearch-prepare

Then you can use any of the other codesearch-* tools, and grepper, and read-file tools
to nagivate the source code related to the crash.

The crash you need to debug is:

------------[ cut here ]------------
UBSAN: array-index-out-of-bounds in fs/jfs/jfs_dmap.c:2976:16
index 1365 is out of range for type 's8[1365]' (aka 'signed char[1365]')
CPU: 1 UID: 0 PID: 6059 Comm: syz.0.17 Not tainted syzkaller #0 PREEMPT_{RT,(full)}
Hardware name: Google Google Compute Engine/Google Compute Engine, BIOS Google 10/25/2025
Call Trace:
 <TASK>
 dump_stack_lvl+0xe8/0x150 lib/dump_stack.c:120
 ubsan_epilogue+0xa/0x40 lib/ubsan.c:233
 __ubsan_handle_out_of_bounds+0xe9/0xf0 lib/ubsan.c:455
 dbFindLeaf+0x308/0x520 fs/jfs/jfs_dmap.c:2976
 dbFindCtl+0x267/0x520 fs/jfs/jfs_dmap.c:1717
 dbAllocAny fs/jfs/jfs_dmap.c:1527 [inline]
 dbAlloc+0x5fa/0xba0 fs/jfs/jfs_dmap.c:878
 diNewIAG fs/jfs/jfs_imap.c:2510 [inline]
 diAllocExt fs/jfs/jfs_imap.c:1905 [inline]
 diAllocAG+0xd45/0x1df0 fs/jfs/jfs_imap.c:1669
 diAlloc+0x1d4/0x1670 fs/jfs/jfs_imap.c:1590
 ialloc+0x8c/0x8f0 fs/jfs/jfs_inode.c:56
 jfs_mkdir+0x193/0xa70 fs/jfs/namei.c:225
 vfs_mkdir+0x52d/0x5d0 fs/namei.c:5130
 do_mkdirat+0x27a/0x4b0 fs/namei.c:5164
 __do_sys_mkdirat fs/namei.c:5186 [inline]
 __se_sys_mkdirat fs/namei.c:5184 [inline]
 __x64_sys_mkdirat+0x87/0xa0 fs/namei.c:5184
 do_syscall_x64 arch/x86/entry/syscall_64.c:63 [inline]
 do_syscall_64+0xec/0xf80 arch/x86/entry/syscall_64.c:94
 entry_SYSCALL_64_after_hwframe+0x77/0x7f
RIP: 0033:0x7efe6c5ade97
Code: 73 01 c3 48 c7 c1 a8 ff ff ff f7 d8 64 89 01 48 83 c8 ff c3 66 2e 0f 1f 84 00 00 00 00 00 0f 1f 44 00 00 b8 02 01 00 00 0f 05 <48> 3d 01 f0 ff ff 73 01 c3 48 c7 c1 a8 ff ff ff f7 d8 64 89 01 48
RSP: 002b:00007efe6bbf4e68 EFLAGS: 00000246 ORIG_RAX: 0000000000000102
RAX: ffffffffffffffda RBX: 00007efe6bbf4ef0 RCX: 00007efe6c5ade97
RDX: 00000000000001ff RSI: 00002000000002c0 RDI: 00000000ffffff9c
RBP: 0000200000000200 R08: 00002000000000c0 R09: 0000000000000000
R10: 0000200000000200 R11: 0000000000000246 R12: 00002000000002c0
R13: 00007efe6bbf4eb0 R14: 0000000000000000 R15: 0000000000000000
 </TASK>
---[ end trace ]---
```
