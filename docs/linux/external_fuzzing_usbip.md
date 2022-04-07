# **USB/IP Fuzzing for Linux Kernel**

Syzkaller supports fuzzing the Linux kernel USB/IP subsystem externally. We can set up a virtual network and send USB/IP packets to the client kernel as they are being received from an external server.
USB/IP fuzzing needs USB/IP configurations to be enabled. You can find the list in the configurations part.

Currently syzkaller only includes support for fuzzing the client side of USB/IP, which consists of 2 main parts:

1. USB/IP pseudo-syscalls.
2. Syzkaller descriptions.

### **Configurations**

Following configurations should be enabled for USB/IP.

```
CONFIG_USBIP_CORE=y
CONFIG_USBIP_VHCI_HCD=y
CONFIG_USBIP_VHCI_HC_PORTS=8
CONFIG_USBIP_VHCI_NR_HCS=8
CONFIG_USBIP_HOST=y
CONFIG_USBIP_VUDC=y
CONFIG_USBIP_DEBUG=y
```

### **Pseudo-syscalls**

Currently syzkaller defines one USB/IP pseudo-syscall and one USB/IP specific write syscall (see [this](/executor/common_linux.h) for the pseudo-syscall and [this](/sys/linux/usbip.txt) for its syzkaller descriptions):

`syz_usbip_server_init` sets up USB/IP server. It creates a pair of connected socket and opens the `/sys/devices/platform/vhci_hcd.0/attach` file. Later, this pseudo-syscall writes the USB/IP client’s socket descriptor as well as port number used for USB/IP connection, USB device id and USB device speed into this file so that the USB/IP communication between client and server can start and client’s kernel can receive USB/IP packets from the server.

`write$usbip_server` sends USB/IP packets to client by using server's socket descriptor. (Particularly, `USBIP_RET_SUBMIT` and `USBIP_RET_UNLINK` packets.) We assume that the server can send arbitrary USB/IP packets instead of emulating a real device. These packets end up in the client's kernel and get parsed there.

### **Further Improvements**

1. Fuzzing the server side of USB/IP.
2. Collect coverage from USB/IP kernel code.
