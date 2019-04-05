# Found Bugs

Most latest bugs are reported by [syzbot](/docs/syzbot.md) to
[syzkaller-netbsd-bugs](https://groups.google.com/forum/#!forum/syzkaller-netbsd-bugs)
mailing list and are listed on the [dashboard](https://syzkaller.appspot.com/netbsd)

Newer bugs come first

- KASAN: connect(2) - missing length check in some protocols causes a out of bounds read - [fix](https://github.com/NetBSD/src/commit/a6926e46f91619f5a231a35b7886dd6c54a65ab3)
10
- KASAN: send(2) - missing length check in some protocols causes a out of bounds read - [fix](https://github.com/NetBSD/src/commit/9e1867da2eb8366dbff200011724a66a4da24503)
- mmap(2): a file descriptor with PaX MPROTECT can produce an unkillable process - [gnats](http://gnats.netbsd.org/52658) - [fix](https://github.com/NetBSD/src/commit/8d45bd6de2c49d27b4f59c70f057d174b47d9278)

