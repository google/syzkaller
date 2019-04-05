# Found bugs

Most latest bugs are reported by [syzbot](/docs/syzbot.md) to
[syzkaller-openbsd-bugs](https://groups.google.com/forum/#!forum/syzkaller-openbsd-bugs)
mailing list and are listed on the [dashboard](https://syzkaller.appspot.com/openbsd).

Newer bugs comes first.

- [bpf(4): negative input accepted in `bpfioctl()`](https://marc.info/?l=openbsd-cvs&m=155430843501793&w=2)

- [sendto: lenient `rtm_hdrlen` validation](https://marc.info/?l=openbsd-cvs&m=155404645328879&w=2)

- [wsmux(4): restrict the number of allowed devices](https://marc.info/?l=openbsd-cvs&m=155393308902921&w=2)

- [rtable(4): out-of-bounds read in `rtable_satoplen()`](https://marc.info/?l=openbsd-cvs&m=155181289205879&w=2)

- [wsmux(4): wrong lock flags](https://marc.info/?l=openbsd-cvs&m=155068528608010&w=2)

- [ioctl: negative input accepted in `spkrioctl()`](https://marc.info/?l=openbsd-cvs&m=155064605025992&w=2)

- [wsmux(4): missing locking](https://marc.info/?l=openbsd-cvs&m=155051156715959&w=2)

- [recvmsg: double free of mbuf](https://marc.info/?l=openbsd-cvs&m=154931648202074&w=2)

- [semop: use-after-free](https://marc.info/?l=openbsd-cvs&m=154926389815162&w=2)

- [kernel: missing lock acquisition during page fault](https://marc.info/?l=openbsd-cvs&m=154917205425885&w=2)

- [ioctl: use-after-free in `wsmux_do_ioctl()`](https://marc.info/?l=openbsd-cvs&m=154900458511494&w=2)

- [ioctl: out of bounds access in `wsmux_do_ioctl()`](https://marc.info/?l=openbsd-cvs&m=154859038916770&w=2)

- [unveil: NULL pointer dereference](https://marc.info/?l=openbsd-cvs&m=154818960525456&w=2)

- [fcntl: use-after-free in `lf_findoverlap()`](https://marc.info/?l=openbsd-cvs&m=154809417426357&w=2)

- [setsockopt: incorrect mbuf padding](https://marc.info/?l=openbsd-cvs&m=154784437622409&w=2)

- [read: missing locking](https://marc.info/?l=openbsd-cvs&m=154715201702848&w=2)

- [write: lenient IP packet validation](https://marc.info/?l=openbsd-cvs&m=154684768026869&w=2)

- [mbuf(9): mutating read-only mbuf](https://marc.info/?l=openbsd-cvs&m=154684739226800&w=2)

- [setrlimit: lock ordering problem in `mi_switch()`](https://marc.info/?l=openbsd-cvs&m=154677960110593&w=2)

- [switch(4): many affected syscalls due to mbuf corruption](https://marc.info/?l=openbsd-cvs&m=154600758019977&w=2)

- [setsockopt: integer overflow in `ip_pcbopts()`](https://marc.info/?l=openbsd-cvs&m=154531248603735&w=2) [ERRATA-64-010](https://ftp.openbsd.org/pub/OpenBSD/patches/6.4/common/010_pcbopts.patch.sig)

- [recv: unexpected mbuf queue growth while sleeping](https://marc.info/?l=openbsd-cvs&m=154506523901003&w=2) [ERRATA-64-009](https://ftp.openbsd.org/pub/OpenBSD/patches/6.4/common/009_recvwait.patch.sig)

- [ioctl: reject inappropriate commands in `wsmux_do_ioctl()`](https://marc.info/?l=openbsd-cvs&m=154507410803526&w=2)

- [getsockopt: errorneous switch fall through in `rip_usrreq()` affecting many socket related syscalls](https://marc.info/?l=openbsd-cvs&m=154383186000797&w=2)

- [shutdown: integer overflow in `unp_internalize()`](https://marc.info/?l=openbsd-cvs&m=154282004307882&w=2) [ERRATA-64-006](https://ftp.openbsd.org/pub/OpenBSD/patches/6.4/common/006_uipc.patch.sig)

- [ioctl: use-after-free in `wsmux_do_ioctl()`](https://marc.info/?l=openbsd-cvs&m=154269457228677&w=2)

- [flock: double free](https://marc.info/?l=openbsd-cvs&m=154070100731996&w=2)

- [poll: execution of address `0x0` caused by console redirection](https://marc.info/?l=openbsd-cvs&m=153552269821957&w=2)

- [kqueue: use-after-free in `kqueue_close()`](https://marc.info/?l=openbsd-cvs&m=153364550327224&w=2)

- [unveil: invalid call to `VOP_UNLOCK()`](https://marc.info/?l=openbsd-cvs&m=153318491427658&w=2)

- [open: NULL pointer dereference while operating on cloned device](https://marc.info/?l=openbsd-cvs&m=153297130613157&w=2)

- [mprotect: incorrect bounds check in `uvm_map_protect()`](https://marc.info/?l=openbsd-cvs&m=153227003430211&w=2)

- [fchown: NULL pointer dereference while operating on cloned device](https://marc.info/?l=openbsd-cvs&m=153224108724940&w=2)

- [recvmsg: double free of mbuf](https://marc.info/?l=openbsd-cvs&m=153067010015474&w=2)

- [ftruncate: NULL pointer dereference while operating on cloned device](https://marc.info/?l=openbsd-cvs&m=153062270701248&w=2)

- [kqueue: NULL pointer dereference](https://marc.info/?l=openbsd-cvs&m=152930020005260&w=2)
