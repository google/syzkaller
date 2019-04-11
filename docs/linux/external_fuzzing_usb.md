External USB fuzzing for Linux kernel
=====================================

# USB fuzzing with syzkaller

This page describes the current state of external USB fuzzing support in syzkaller.
Note, that it's still in development and things might change.

This allowed to find over [80 bugs](/docs/linux/found_bugs_usb.md) in the Linux kernel USB stack so far.

How to set this up:

1. Checkout the `usb-fuzzer` branch from https://github.com/google/kasan

2. Configure and build the kernel. You need to enable `CONFIG_USB_FUZZER=y`, `CONFIG_USB_DUMMY_HCD=y` and all the USB drivers you're interested in fuzzing:

   ```
   menu config -> Device Drivers -> USB Support ->
     -> USB Gadget Support (enable) ->
       -> USB Peripheral Controller -> Dummy HCD (enable)
       -> USB Gadget Fuzzer (enable)
   ```

3. Update syzkaller descriptions by extracting USB device info using the instructions below.

4. Enable `syz_usb_connect`, `syz_usb_disconnect`, `syz_usb_control_io` and `syz_usb_ep_write` syscalls in the manager config.

5. Set `sandbox` to `none` in the manager config.

6. Pass `dummy_hcd.num=8` to the kernel command line in the maganer config.

7. Run.

Syzkaller descriptions for USB fuzzing can be found here: [1](/sys/linux/vusb.txt), [2](/sys/linux/init_vusb.go) and [3](/sys/linux/init_vusb_ids.go).


## Updating syzkaller USB descriptions

1. Apply [this](/tools/syz-usbgen/usb_ids.patch) kernel patch.

2. Build and boot the kernel.

3. Connect some USB device to it (e.g. with `syz-exeprog usb.log`, where `usb.log` is some program that utilizes the `syz_usb_connect` syzcall).

4. Use [syz-usbgen](/tools/syz-usbgen/usbgen.go) script to update [syzkaller descriptions](/sys/linux/init_vusb_ids.go).
