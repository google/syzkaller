External network fuzzing for Linux kernel
=========================================

syzkaller has support for external fuzzing of the network stack.
This is achieved by using the [TUN/TAP](https://www.kernel.org/doc/Documentation/networking/tuntap.txt) interface.
It allows to set up a virtual network interface and send packets to the kernel as they are being received from an external network.
This triggers the same paths as a real packet delivered through a real network interface (except for the driver layer).

You need to enable the `CONFIG_TUN` kernel config to enable external network fuzzing.
See `initialize_tun()` in [executor/common_linux.h](/executor/common_linux.h) for the exact way the virtual interface is set up.

The template descriptions can be found in [sys/linux/vnet.txt](/sys/linux/vnet.txt).
At this moment there are 2 fake syscalls: `syz_emit_ethernet` and `syz_extract_tcp_res`.
The first one externally sends a packet through the virtual interface.
The second one tries to externally receive a packet back and parse TCP sequence numbers from it for use in subseqent packets.
There many protocols or protocol extensions that are not described yet, so the additions are welcome!

Since fuzzing may be done in mutiple executor proccesses within the same VM instance, we need a way to isolate the virtual network for different executors.
Right now this is done by creating one virtual interface per executor and assigning different MAC, IPv4 and IPv6 addresses to each of these interfaces.
Then the template descriptions make use of the `proc` type to generate proper addresses for each executor.

Since many network protocols require checksum fields to be embedded into packets, there's a support for describing such fields.
There's a `csum` type, which right now supports two different kinds of checksumming:
[the Internet checksum](https://tools.ietf.org/html/rfc1071): `csum csum[parent, inet, int16be]`,
and TCP-like pseudo header checksum: `csum csum[tcp_packet, pseudo, IPPROTO_TCP, int16be]`.
The checksums are computed and embedded right before emitting a packet though the virtual interface.
There's also a nice feature: when syzkaller generates a C reproducer, it generates code to compute checksums in runtime as well.
