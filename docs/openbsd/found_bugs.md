# Found bugs

Most latest bugs are reported by [syzbot](/docs/syzbot.md) to
[syzkaller-openbsd-bugs](https://groups.google.com/forum/#!forum/syzkaller-openbsd-bugs)
mailing list and are listed on the [dashboard](https://syzkaller.appspot.com/#openbsd).

Newer bugs comes first.

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
