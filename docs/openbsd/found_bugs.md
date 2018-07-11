# Found bugs

Git commit hashes are not considered stable,
the relevant CVS revisions are therefore also included.
Newer bugs comes first.

- [kqueue: use-after-free in `kqueue_close()`](https://github.com/openbsd/src/commit/4c035d0786d583e0761a97aa87b27f8463a98730)
  - sys/kern/kern_event.c r1.95

- [unveil: invalid call to `VOP_UNLOCK()`](https://github.com/openbsd/src/commit/f993c6f7844b25fe298d121c5af2d511a74112bf)
  - sys/kern/vfs_lookup.c r1.73

- [open: NULL pointer dereference while operating on cloned device](https://github.com/openbsd/src/commit/43ae0e2115f5b86d1be2559c86e9b7163c7423ec)
  - sys/kern/vfs_syscalls.c r1.299

- [mprotect: incorrect bounds check in `uvm_map_protect()`](https://github.com/openbsd/src/commit/9f4e9fc9c86f6c8ab1c1cf246d58d998924e0f88)
  - sys/uvm/uvm_map.c r1.238

- [fchown: NULL pointer dereference while operating on cloned device](https://github.com/openbsd/src/commit/6ea176221704e8bd4864f0cf0128f48cbe45de4d)
  - sys/kern/vfs_syscalls.c r1.295

- [recvmsg: double free of mbuf](https://github.com/openbsd/src/commit/07be777edd677edbb0d583a1a89fa2d191ffe3c4)
  - sys/netinet/raw_ip.c r1.110
  - sys/netinet6/raw_ip6.c r1.128

- [ftruncate: NULL pointer dereference while operating on cloned device](https://github.com/openbsd/src/commit/c0699e5ad0a715e2ac33136d290401755f533f7d)
  - sys/kern/vfs_vnops.c r1.94

- [kqueue: NULL pointer dereference](https://github.com/openbsd/src/commit/316aeb9f5cfd5f384286f52faed4f6138548c480)
  - sys/kern/kern_descrip.c r1.165
  - sys/kern/kern_event.c r1.93
  - sys/kern/kern_fork.c r1.203
  - sys/sys/eventvar.h r1.5
  - sys/sys/filedesc.h r1.38
  - sys/sys/proc.h r1.249
