External USB fuzzing for Linux kernel
=====================================

This is in a prototype stage, there's still a lot of things to fix and implement.

syzkaller has support for external fuzzing of the USB stack.
Initially it was based on gadgetfs, but later switched to another gadgetfs-like driver written from scratch.
It allows to connect virtual USB devices from a userspace application as if they are being plugged into a USB port.

This allowed to find over [80 bugs](/docs/linux/found_bugs_usb.md) in the Linux kernel USB stack so far.

How to set this up:

1. Checkout upstream Linux kernel (all the patches linked below are based on 4.15-rc3).

2. Apply two patches to the kernel: [1](/tools/usb/0001-usb-fuzzer-add-hub-hijacking-ioctl.patch) and [2](/tools/usb/0002-usb-fuzzer-main-usb-gadget-fuzzer-driver.patch).

    Patch #1 allows to synchonously proccess events on a USB hub.
    This is required by syzkaller for proper coverage collection, since kcov can only collect coverage of the current thread.
    Patch #2 add another kernel interface (`/sys/kernel/debug/usb-fuzzer`) for emulating USB devices.

3. Configure and build the kernel. You need to enable `CONFIG_USB_FUZZER=y` and `CONFIG_USB_DUMMY_HCD=y`:

   ```
   menu config -> Device Drivers -> USB Support ->
     -> USB Gadget Support (enable) -> 
       -> USB Peripheral Controller -> Dummy HCD (enable)
       -> USB Gadget Fuzzer (enable)
   ```

   [This](/tools/usb/kernel-config) is the config I used for testing the upstream kernel.

4. Optionally update syzkaller descriptions by extracting USB device info by using the instructions below.

5. Checkout syzkaller `usb-fuzzer` branch, build syzkaller.

6. Enable `syz_usb_connect` and `syz_usb_disconnect` syscalls in the manager config.

7. Run.

Syzkaller descriptions for USB fuzzing can be found here: [1](/sys/linux/vusb.txt) and [2](/sys/linux/vusb_ids.txt).


## Extracting USB device ids

Part of the syzkaller descriptions for USB fuzzing are generated based on the drivers enabled in a particular kernel with a particular kernel config.
These descritions help syzkaller to discover enabled USB drivers.
The [current descriptions](/sys/linux/vusb_ids.txt) are generated for upstream kernel (4.15-rc3) using [this config](/tools/usb/kernel-config).
If you wish to generate descriptions for your kernel with your config follow the instructions below.

1. Apply [this patch](/tools/usb/0003-usb-fuzzer-dump-usb-device-ids-on-enumeration.patch) on top of the two described above.

    When a new device is being probed the kernel goes over a list of all USB device drivers it has loaded and tries to find the matching one.
    This patch makes kernel print info about all USB devices it tries to the kernel log.

2. Compile and run [this program](/tools/usb/usb_ids_dump.c).

    This program connects a virtual USB device, that doesn't have a matching driver.
    As a result the kernel will print info about all device drivers it had.

3. Collect USB device info:

    ```
    cat kernel.log | grep -E '] [0-9a-f]{48}' | cut -c 16- | sort | uniq > usb_ids_dump
    ```

    For reference, the resulting `usb_ids_dump` for upstream kernel can be found [here](/tools/usb/usb_ids_dump).

4. Generate syzkaller descriptions based on the USB devices info using [this script](/tools/usb/usb_ids_parse.py):

    ```
    ./usb_ids_parse.py ./usb_ids_dump > /syzkaller/sys/linux/vusb_ids.txt
    ```

5. Run `make generate`.

6. Rebuild and run syzkaller.
