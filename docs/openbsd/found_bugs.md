# Found bugs

Most latest bugs are reported by [syzbot](/docs/syzbot.md) to
[syzkaller-openbsd-bugs](https://groups.google.com/forum/#!forum/syzkaller-openbsd-bugs)
mailing list and are listed on the [dashboard](https://syzkaller.appspot.com/openbsd).

Newer bugs comes first.

- [wsmux(4): use-after-free](https://marc.info/?l=openbsd-cvs&m=159600205025410&w=2)

- [pty(4): machine lockup due to expensive retyping](https://marc.info/?l=openbsd-cvs&m=159473720602522&w=2)

- [sysctl(2): lenient validation of `net.inet.tcp.synbucketlimit`](https://marc.info/?l=openbsd-cvs&m=159249199005451&w=2)

- [tty(4): infinite sleep during close](https://marc.info/?l=openbsd-cvs&m=158892312627663&w=2)

- [inet6(4): lenient validation in `ip6_pullexthdr()`](https://marc.info/?l=openbsd-cvs&m=158874895026819&w=2)

- [inet6(4): mutating static routes](https://marc.info/?l=openbsd-cvs&m=158754155106430&w=2)

- [pf(4): lenient validation in `pf_rulecopyin()`](https://marc.info/?l=openbsd-cvs&m=158733548829486&w=2)

- [sosplice(9): socket lock already held](https://marc.info/?l=openbsd-cvs&m=158670814206616&w=2)

- [vmm(4): out-of-bounds read](https://marc.info/?l=openbsd-cvs&m=158548168627386&w=2)

- [VOP_LOCK(9): too strict lockcount assertion](https://marc.info/?l=openbsd-cvs&m=158529591303747&w=2)

- [wsmux(4): use-after-free](https://marc.info/?l=openbsd-cvs&m=158503642507991&w=2)

- [sosplice(9): unbound recursion](https://marc.info/?l=openbsd-cvs&m=158396530407996&w=2)

- [shmctl: use-after-free due to sleeping](https://marc.info/?l=openbsd-cvs&m=158330910903824&w=2)

- [kqueue: interrupt race](https://marc.info/?l=openbsd-cvs&m=158191244405065&w=2)

- [pf(4): unhandled address families](https://marc.info/?l=openbsd-cvs&m=157852015714603&w=2)

- [uvm(9): incorrect offset calculation in `uvm_share(9)`](https://marc.info/?l=openbsd-cvs&m=157544812928708&w=2)

- [vmm(4): wrong virtual memory structure type](https://marc.info/?l=openbsd-cvs&m=157544746828404&w=2)

- [tun(4): interface creation race](https://marc.info/?l=openbsd-cvs&m=157412200313814&w=2)

- [ioctl: lenient validation of interface address](https://marc.info/?l=openbsd-cvs&m=157313316301838&w=2)

- [shmctl: use-after-free due to sleeping](https://marc.info/?l=openbsd-cvs&m=157229269222248&w=2)

- [bpf(4): missing reference counting](https://marc.info/?l=openbsd-cvs&m=157169894124474&w=2)

- [unveil: do not increment `ps_uvncount` more than once per unveiled path](https://marc.info/?l=openbsd-cvs&m=156995587324429&w=2)

- [sendto: lenient validation of socket address](https://marc.info/?l=openbsd-cvs&m=156923645331466&w=2)

- [vmm(4): missing locking](https://marc.info/?l=openbsd-cvs&m=156822096707365&w=2)

- [vmm(4): number of VMs counter overflow](https://marc.info/?l=openbsd-cvs&m=156814418919992&w=2)

- [ip6(4): use-after-free in multicast route](https://marc.info/?l=openbsd-cvs&m=156761352927972&w=2)

- [VOP_LOCK(9): threads not observing exclusive lock](https://marc.info/?l=openbsd-cvs&m=156684581030011&w=2)

- [ip6(4): don't use the flow of the first fragment to store ECN data](https://marc.info/?l=openbsd-cvs&m=156684528429904&w=2 )

- [acct: `vn_close(9)` race](https://marc.info/?l=openbsd-cvs&m=156585417104888&w=2)

- [diskmap(4): side-effect in error path](https://marc.info/?l=openbsd-cvs&m=156499481623952&w=2)

- [rtable_walk(9): stack exhausted due to recursion](https://marc.info/?l=openbsd-cvs&m=156113711405665&w=2)

- [ftruncate: side-effect in error path](https://marc.info/?l=openbsd-cvs&m=156084321808087&w=2)

- [sendto: missing presence check of `RTF_MPLS` flag](https://marc.info/?l=openbsd-cvs&m=156041373709268&w=2)

- [sendto: comparison of non-canonical sockaddr](https://marc.info/?l=openbsd-cvs&m=156041354609207&w=2)

- [ioctl: NULL pointer dereference in `mrt_ioctl` and `mrt6_ioctl`](https://marc.info/?l=openbsd-cvs&m=155966468511915&w=2)

- [pckbc(4): command queue corruption](https://marc.info/?l=openbsd-cvs&m=155958041916637&w=2)

- [wsmux(4): use-after-free in `wsmux_do_ioctl()`](https://marc.info/?l=openbsd-cvs&m=155847224722518&w=2)

- [sendto: lenient validation in `rt_mpls_set()`](https://marc.info/?l=openbsd-cvs&m=155759323213186&w=2)

- [bpf(4): unsigned integer wrap around](https://marc.info/?l=openbsd-cvs&m=155621669009140&w=2)

- [vmm(4): `printf()` called from IPI-context](https://marc.info/?l=openbsd-cvs&m=155590526807190&w=2)

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
