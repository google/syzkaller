# Found Bugs

Newer bugs come first

- [Check the index hasn't changed after writing the cmp entry.](https://reviews.freebsd.org/rS344517)
- [Fix a locking issue in the IPPROTO_SCTP level SCTP_PEER_ADDR_THLDS socket](https://reviews.freebsd.org/rS343960)
- [Fix a locking bug in the IPPROTO_SCTP level SCTP_EVENT socket option.](https://reviews.freebsd.org/rS343954)
- [Fix locking for IPPROTO_SCTP level SCTP_DEFAULT_PRINFO socket option.](https://reviews.freebsd.org/rS343951)
- [Fix an off-by-one error in the input validation of the SCTP_RESET_STREAMS socketoption.](https://reviews.freebsd.org/rS343769)
- [Limit the user-controllable amount of memory the kernel allocates via IPPROTO_SCTP level socket options.](https://reviews.freebsd.org/rS343089)
- [Fix getsockopt() for IP_OPTIONS/IP_RETOPTS.](https://reviews.freebsd.org/rS342879)
- [Avoid overfow in vtruncbuf()](https://reviews.freebsd.org/rS342857)
- [Limit option_len for the TCP_CCALGOOPT.](https://reviews.freebsd.org/rS341335)
- [Correct vm_fault_copy_entry() handling of backing file truncation after the file mapping was wired.](https://reviews.freebsd.org/rS338999)
- [In vm_fault_copy_entry(), we should not assert that entry is charged if the dst_object is not of swap type.](https://reviews.freebsd.org/rS338998)
- [Handle a guest executing a vm instruction by trapping and raising an undefined instruction exception.](https://reviews.freebsd.org/rS338957)
- [disallow clock_settime too far in the future to avoid panic](https://reviews.freebsd.org/rS325825)
- [Fix parsing error when processing cmsg in SCTP send calls.](https://reviews.freebsd.org/rS325046)
