External USB fuzzing for Linux kernel
=====================================

Syzkaller supports fuzzing the Linux kernel USB subsystem externally
(as it would be done by plugging in a physical USB device with e.g. [Facedancer](https://github.com/usb-tools/Facedancer)).
This allowed to find over [200 bugs](/docs/linux/found_bugs_usb.md) in the Linux kernel USB stack so far.
This is still in development and things might change.

USB fuzzing support consists of 3 parts:

1. Syzkaller changes that are now upstream.
2. Kernel interface for USB device emulation, which can be found [here](https://github.com/google/kasan/commits/usb-fuzzer) and is now being upstreamed.
3. KCOV changes that allow to collect coverage from background threads and interrupts
(the former is now upstream, the latter can be found [here](https://github.com/google/kasan/commits/usb-fuzzer) and is now being upstreamed).

More details can be found:

1. In the OffensiveCon 2019 "Coverage-Guided USB Fuzzing with Syzkaller" talk
([slides](https://docs.google.com/presentation/d/1z-giB9kom17Lk21YEjmceiNUVYeI6yIaG5_gZ3vKC-M/edit?usp=sharing), [video](https://www.youtube.com/watch?v=1MD5JV6LfxA)).
2. In [this](https://marc.info/?l=linux-usb&m=155551883403285&w=2) email.

A few major things that need to be done:

1. Upstream KCOV changes that allow to collect coverage from interrupts.
2. Upstream the kernel interface for USB device emulation.
3. Implement a proper way for extracting relevant USB ids from the kernel ([discussion](https://www.spinics.net/lists/linux-usb/msg187915.html) is ongoing).
4. Add descriptions for all relevant USB classes and drivers.

The work on points 1 and 2 has started:

Kernel patches in mainline:

- [kcov: remote coverage support](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=eec028c9386ed1a692aa01a85b55952202b41619)
- [kcov: fix struct layout for kcov_remote_arg](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=a69b83e1ae7f6c5ff2cc310870c1708405d86be2)
- [usb, kcov: collect coverage from hub_event](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=95d23dc27bde0ab4b25f7ade5e2fddc08dd97d9b)
- [USB: dummy-hcd: use usb_urb_dir_in instead of usb_pipein](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=6dabeb891c001c592645df2f477fed9f5d959987)
- [USB: dummy-hcd: increase max number of devices to 32](https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=8442b02bf3c6770e0d7e7ea17be36c30e95987b6)
- (All other patches that touch drivers/usb/gadget/udc/dummy_hcd.c are recommended.)

Kernel patches in review:

- [[v4] usb: gadget: add raw-gadget interface](https://patchwork.kernel.org/cover/11301723/)
- [[RFC] kcov: collect coverage from usbhid interrupts](https://patchwork.kernel.org/cover/11288771/)

Some ideas for things that can be done:

1. Add a mode for standalone fuzzing of physical USB hosts (by using e.g. Raspberry Pi Zero, see below).
This includes at least: a. making sure that current USB emulation implementation works properly on different OSes (there are some differences);
b. using USB requests coming from the host as a signal (like coverage) to enable "signal-driven" fuzzing,
c. making UDC driver name configurable for syz-execprog and syz-prog2c.
2. Generate syzkaller programs from usbmon trace that is produced by actual USB devices (this should make the fuzzer to go significantly deeper into the USB drivers code).


## Internals

Currently syzkaller defines 5 USB syzcalls (see [this](/sys/linux/vusb.txt) and [this](/executor/common_usb.h)):

1. `syz_usb_connect` - connects a USB device.
2. `syz_usb_disconnect` - disconnects a USB device.
3. `syz_usb_control_io` - sends or receives a control message over endpoint 0.
4. `syz_usb_ep_write` - sends a message to an endpoint.
4. `syz_usb_ep_read` - receives a message from an endpoint.

Syzkaller descriptions for USB fuzzing can be found [here](/sys/linux/vusb.txt).


## Setting up

1. Checkout the `usb-fuzzer` branch from https://github.com/google/kasan

2. Configure the kernel (at the very least `CONFIG_USB_RAW_GADGET=y` and `CONFIG_USB_DUMMY_HCD=y` need to be enabled).

    The easiest option is to use the [config](/dashboard/config/upstream-usb.config) from the syzbot USB fuzzing instance.

    Another option is to use the USB config generation [script](/dashboard/config/generate-config-usb.sh).
    This script allows to extract enabled USB related configs from a set of existing `.config` files.
    Right now it extracts configs only from [one](/dashboard/config/distros) of the Ubuntu kernel's configs.

    ``` bash
    cd ./dashboard/config/
    # Put relevant .configs into ./distros/
    CC=$COMPILER_BINARY_PATH SOURCEDIR=$KERNEL_SOURCE_PATH ./generate-config-usb.sh
    ```

3. Build the kernel.

4. Optionally update syzkaller descriptions by extracting USB IDs using the instructions below.

5. Enable `syz_usb_connect`, `syz_usb_disconnect`, `syz_usb_control_io`, `syz_usb_ep_write` and `syz_usb_ep_read` syzcalls in the manager config.

6. Set `sandbox` to `none` in the manager config.

7. Pass `dummy_hcd.num=8` to the kernel command line in the maganer config.

8. Run.


## Updating syzkaller USB IDs

Syzkaller uses a list of hardcoded [USB IDs](/sys/linux/init_vusb_ids.go) that are [patched](/sys/linux/init_vusb.go) into the `syz_usb_connect` syzcall by syzkaller runtime.
One of the ways to make syzkaller target only particular USB drivers is to alter that list.
The instructions below describe a hackish way to generate syzkaller USB IDs for all USB drivers enabled in your .config.

1. Apply [this](/tools/syz-usbgen/usb_ids.patch) kernel patch.

2. Build and boot the kernel.

3. Connect a USB HID device. In case you're using a `CONFIG_USB_RAW_GADGET=y` kernel, use the provided [keyboard emulation program](/tools/syz-usbgen/keyboard.c).

4. Use [syz-usbgen](/tools/syz-usbgen/usbgen.go) script to update [syzkaller descriptions](/sys/linux/init_vusb_ids.go):

    ```
    ./bin/syz-usbgen KERNEL_LOG ./sys/linux/init_vusb_ids.go
    ```

5. Don't forget to revert the applied patch and rebuild the kernel before doing actual fuzzing.


## Running reproducers with Raspberry Pi Zero W

It's possible to run syzkaller USB reproducers by using a Linux board plugged into a physical USB host.
These instructions describe how to set this up on a Raspberry Pi Zero W, but any other board that has a working USB UDC driver can be used as well.

1. Download `raspbian-stretch-lite.img` from [here](https://www.raspberrypi.org/downloads/raspbian/).

2. Flash the image into an SD card as described [here](https://www.raspberrypi.org/documentation/installation/installing-images/linux.md).

3. Enable UART as described [here](https://www.raspberrypi.org/documentation/configuration/uart.md).

4. Boot the board and get a shell over UART as described [here](https://learn.adafruit.com/raspberry-pi-zero-creation/give-it-life). You'll need a USB-UART module for that. The default login credentials are `pi` and `raspberry`.

5. Get the board connected to the internet (plug in a USB Ethernet adapter or follow [this](https://www.raspberrypi.org/documentation/configuration/wireless/wireless-cli.md)).

6. Update: `sudo apt-get update && sudo apt-get dist-upgrade && sudo rpi-update && sudo reboot`.

7. Install useful packages: `sudo apt-get install vim git`.

8. Download and install Go:

    ``` bash
    curl https://dl.google.com/go/go1.10.8.linux-armv6l.tar.gz -o go1.10.8.linux-armv6l.tar.gz
    tar -xf go1.10.8.linux-armv6l.tar.gz
    mv go goroot-1.10.8
    mkdir gopath-1.10.8
    export GOPATH=~/gopath-1.10.8
    export GOROOT=~/goroot-1.10.8
    export PATH=~/goroot-1.10.8/bin:$PATH
    export PATH=~/gopath-1.10.8/bin:$PATH
    ```

9. Download syzkaller, apply the patch below and build `syz-executor`:

    ``` c
    diff --git a/executor/common_usb.h b/executor/common_usb.h
    index e342d808..278c2f4e 100644
    --- a/executor/common_usb.h
    +++ b/executor/common_usb.h
    @@ -269,9 +269,7 @@ static volatile long syz_usb_connect(volatile long a0, volatile long a1, volatil
    
            // TODO: consider creating two dummy_udc's per proc to increace the chance of
            // triggering interaction between multiple USB devices within the same program.
    -       char device[32];
    -       sprintf(&device[0], "dummy_udc.%llu", procid);
    -       rv = usb_raw_init(fd, speed, "dummy_udc", &device[0]);
    +       rv = usb_raw_init(fd, speed, "20980000.usb", "20980000.usb");
            if (rv < 0) {
                    debug("syz_usb_connect: usb_raw_init failed with %d\n", rv);
                    return rv;
    diff --git a/executor/executor.cc b/executor/executor.cc
    index 34949a01..1afcb288 100644
    --- a/executor/executor.cc
    +++ b/executor/executor.cc
    @@ -604,8 +604,8 @@ retry:
                            call_extra_cover = true;
                    }
                    if (strncmp(syscalls[call_num].name, "syz_usb_connect", strlen("syz_usb_connect")) == 0) {
    -                       prog_extra_timeout = 2000;
    -                       call_extra_timeout = 2000;
    +                       prog_extra_timeout = 5000;
    +                       call_extra_timeout = 5000;
                    }
                    if (strncmp(syscalls[call_num].name, "syz_usb_control_io", strlen("syz_usb_control_io")) == 0)
                            call_extra_timeout = 300;
    ```

    ``` bash
    go get -u -d github.com/google/syzkaller/...
    cd ~/gopath-1.10.8/src/github.com/google/syzkaller
    # Put the patch above into ./syzkaller.patch
    git apply ./syzkaller.patch
    make executor
    mkdir ~/syz-bin
    cp bin/linux_arm/syz-executor ~/syz-bin/
    ```

10. Build `syz-execprog` on your host machine for arm32 with `make TARGETARCH=arm execprog` and copy to `~/syz-bin` onto the SD card. You may try building syz-execprog on the Raspberry Pi itself, but that worked poorly for me due to large memory consumption during the compilation process.

11. Make sure that ou can now execute syzkaller programs:

    ``` bash
    cat socket.log
    r0 = socket$inet_tcp(0x2, 0x1, 0x0)
    sudo ./syz-bin/syz-execprog -executor ./syz-bin/syz-executor -threaded=0 -collide=0 -procs=1 -enable='' -debug socket.log
    ```

12. Setup the dwc2 USB gadget driver:

    ```
    echo "dtoverlay=dwc2" | sudo tee -a /boot/config.txt
    echo "dwc2" | sudo tee -a /etc/modules
    sudo reboot
    ```

13. Get Linux kernel headers following [this](https://github.com/notro/rpi-source/wiki).

14. Download the USB Raw Gadget module:

    ``` bash
    mkdir module
    cd module
    wget https://raw.githubusercontent.com/google/kasan/usb-fuzzer/drivers/usb/gadget/raw.c
    wget https://raw.githubusercontent.com/google/kasan/usb-fuzzer/include/uapi/linux/usb/raw-gadget.h
    ```

    Apply the following change:

    ``` c
    diff --git a/raw.c b/raw.c
    index 308c540..68d43b9 100644
    --- a/raw.c
    +++ b/raw.c
    @@ -17,7 +17,7 @@
     #include <linux/usb/gadgetfs.h>
     #include <linux/usb/gadget.h>
     
    -#include <uapi/linux/usb/raw-gadget.h>
    +#include "raw-gadget.h"
     
     #define        DRIVER_DESC "USB Raw Gadget"
     #define DRIVER_NAME "raw-gadget"
    ```

    Add a `Makefile`:

    ``` make
    obj-m := raw.o
    KDIR := /lib/modules/$(shell uname -r)/build
    PWD := $(shell pwd)
    default:
    	$(MAKE) -C $(KDIR) SUBDIRS=$(PWD) modules
    ```

    And build with `make`.

15. Insert the module with `sudo insmod raw.ko`.

16. Build and test the [keyboard emulator program](/tools/syz-usbgen/keyboard.c):

    ``` bash
    # Connect the board to some USB host.
    wget https://raw.githubusercontent.com/google/syzkaller/master/tools/syz-usbgen/keyboard.c
    # Apply the patch below.
    gcc keyboard.c -o keyboard
    sudo ./keyboard
    # Make sure you see the letter 'x' being entered on the host.
    ```

    ``` c
    diff --git a/tools/syz-usbgen/keyboard.c b/tools/syz-usbgen/keyboard.c
    index 2a6015d4..3ebd1e03 100644
    --- a/tools/syz-usbgen/keyboard.c
    +++ b/tools/syz-usbgen/keyboard.c
    @@ -95,8 +95,8 @@ int usb_raw_open() {
     void usb_raw_init(int fd, enum usb_device_speed speed) {
            struct usb_raw_init arg;
            arg.speed = speed;
    -       arg.driver_name = "dummy_udc";
    -       arg.device_name = "dummy_udc.0";
    +       arg.driver_name = "20980000.usb";
    +       arg.device_name = "20980000.usb";
            int rv = ioctl(fd, USB_RAW_IOCTL_INIT, &arg);
            if (rv != 0) {
                    perror("ioctl(USB_RAW_IOCTL_INIT)");
    ```

17. You should now be able to execute syzkaller USB programs:

    ``` bash
    $ cat usb.log
    r0 = syz_usb_connect(0x0, 0x24, &(0x7f00000001c0)={{0x12, 0x1, 0x0, 0x8e, 0x32, 0xf7, 0x20, 0xaf0, 0xd257, 0x4e87, 0x0, 0x0, 0x0, 0x1, [{{0x9, 0x2, 0x12, 0x1, 0x0, 0x0, 0x0, 0x0, [{{0x9, 0x4, 0xf, 0x0, 0x0, 0xff, 0xa5, 0x2c}}]}}]}}, 0x0)
    $ sudo ./syz-bin/syz-execprog -executor ./syz-bin/syz-executor -threaded=0 -collide=0 -procs=1 -enable='' -debug usb.log
    ```

18. Steps 19 through 21 are optional. You may use a UART console and a normal USB cable instead of ssh and Zero Stem.

19. Follow [this](https://www.raspberrypi.org/documentation/configuration/wireless/access-point.md) to setup Wi-Fi hotspot.

20. Follow [this](https://www.raspberrypi.org/documentation/remote-access/ssh/) to enable ssh.

21. Optionally solder [Zero Stem](https://zerostem.io/) onto your Raspberry Pi Zero W.

21. You can now connect the board to an arbitrary USB port, wait for it to boot, join its Wi-Fi network, ssh onto it, and run arbitrary syzkaller USB programs.
