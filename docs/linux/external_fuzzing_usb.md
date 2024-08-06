External USB fuzzing for Linux kernel
=====================================

Syzkaller supports fuzzing the Linux kernel USB subsystem externally (as can be done by plugging in a programmable USB device like [Facedancer](https://github.com/usb-tools/Facedancer)). This allowed finding over [300 bugs](/docs/linux/found_bugs_usb.md) in the Linux kernel USB stack so far.

USB fuzzing support consists of 3 parts:

1. Syzkaller changes; see the [Internals](/docs/linux/external_fuzzing_usb.md#Internals) section for details.
2. Kernel interface for USB device emulation called [Raw Gadget](https://github.com/xairy/raw-gadget), which is now in the mainline kernel.
3. KCOV changes that allow to collect coverage from background kernel threads and interrupts, which are now in the mainline kernel.

See the OffensiveCon 2019 [Coverage-Guided USB Fuzzing with Syzkaller](https://docs.google.com/presentation/d/1z-giB9kom17Lk21YEjmceiNUVYeI6yIaG5_gZ3vKC-M/edit?usp=sharing) talk ([video](https://www.youtube.com/watch?v=1MD5JV6LfxA)) for some (partially outdated) details.

As USB fuzzing requires kernel side support, for non-mainline kernels you need all mainline patches that touch `drivers/usb/gadget/udc/dummy_hcd.c`, `drivers/usb/gadget/legacy/raw_gadget.c` and `kernel/kcov.c`.


## Internals

Currently, syzkaller defines 6 USB pseudo-syscalls (see [syzlang descriptions](/sys/linux/vusb.txt) and [pseudo-syscalls](/executor/common_usb.h) [implementation](/executor/common_usb_linux.h), which relies on the Raw Gadget interface linked above):

1. `syz_usb_connect` - connects a USB device. Handles all requests to the control endpoint until a `SET_CONFIGURATION` request is received.
2. `syz_usb_connect_ath9k` - connects an `ath9k` USB device. Compared to `syz_usb_connect`, this syscall also handles firmware download requests that happen after `SET_CONFIGURATION` for the `ath9k` driver.
3. `syz_usb_disconnect` - disconnects a USB device.
4. `syz_usb_control_io` - sends or receives a control message over endpoint 0.
5. `syz_usb_ep_write` - sends a message to a non-control endpoint.
6. `syz_usb_ep_read` - receives a message from a non-control endpoint.

These pseudo-syscalls targeted at a few different layers:

1. USB core enumeration process is targeted by the generic `syz_usb_connect` variant. As the USB device descriptor fields for this pseudo-syscall get [patched](/sys/linux/init_vusb.go) by syzkaller runtime, `syz_usb_connect` also briefly targets the enumeration process of various USB drivers.
2. Enumeration process for class-specific drivers is targeted by `syz_usb_connect$hid`, `syz_usb_connect$cdc_ecm`, etc. (the device descriptors provided to them have fixed identifying USB IDs to always match to the same USB class driver) accompanied by matching `syz_usb_control_io$*` pseudo-syscalls.
3. Subsequent communication through non-control endpoints for class-specific drivers is not targeted by existing descriptions yet for any of the supported classes. But it can be triggered through generic `syz_usb_ep_write` and `syz_usb_ep_read` pseudo-syscalls.
4. Enumeration process for device-specific drivers is not covered by existing descriptions yet.
5. Subsequent communication through non-control endpoints for device-specific drivers is partially described only for `ath9k` driver via `syz_usb_connect_ath9k`, `syz_usb_ep_write$ath9k_ep1` and `syz_usb_ep_write$ath9k_ep2` pseudo-syscalls.

There are [runtests](/sys/linux/test/) for USB pseudo-syscalls. They are named starting with the `vusb` prefix and can be run with:

```
./bin/syz-manager -config usb-manager.cfg -mode run-tests -tests vusb
```


## Things to improve

The core support for USB fuzzing is in place, but there's still a place for improvements:

1. Remove the device from `usb_devices` in `syz_usb_disconnect` and don't call `lookup_usb_index` multiple times within `syz_usb_connect`. Currently, this causes some reproducers to have the `repeat` flag set when it's not required.

2. Add descriptions for more relevant USB classes and drivers.

3. Resolve TODOs from [sys/linux/vusb.txt](/sys/linux/vusb.txt).

4. Implement a proper way for dynamically extracting relevant USB ids from the kernel (a related [discussion](https://www.spinics.net/lists/linux-usb/msg187915.html)).

5. Add a mode for standalone fuzzing of physical USB hosts (by using Raspberry Pi Zero, see below).
This includes at least: a. making sure that current USB emulation implementation works properly on different OSes (there are some [differences](https://github.com/RoganDawes/LOGITacker/blob/USB_host_enum/fingerprint_os.md#derive-the-os-from-the-fingerprint) in protocol implementation);
b. using USB requests coming from the host as a signal (like coverage) to enable "signal-driven" fuzzing,
c. making UDC driver name configurable for `syz-execprog` and `syz-prog2c`.

6. Generate syzkaller programs from usbmon trace that is produced by actual USB devices (this should make the fuzzer to go significantly deeper into the USB drivers code).


## Setting up

1. Make sure the version of the kernel you're using is at least 5.7. It's recommended to backport all kernel patches that touch kcov, USB Raw Gadget, and USB Dummy UDC/HCD.

2. Configure the kernel: at the very least, `CONFIG_USB_RAW_GADGET=y` and `CONFIG_USB_DUMMY_HCD=y` must be enabled.

    The easiest option is to use the [config](/dashboard/config/linux/upstream-usb.config) from the syzbot USB fuzzing instance.

3. Build the kernel.

4. Optionally update syzkaller descriptions by extracting USB IDs using the [instructions](/docs/linux/external_fuzzing_usb.md#updating-syzkaller-usb-ids) below.

5. Enable `syz_usb_connect`, `syz_usb_disconnect`, `syz_usb_control_io`, `syz_usb_ep_write` and `syz_usb_ep_read` pseudo-syscalls in the manager config.

6. Set `sandbox` to `none` in the manager config.

7. Pass `dummy_hcd.num=8` (or whatever number you use for `procs`) to the kernel command line in the manager config.

8. Run.


## Updating syzkaller USB IDs

Syzkaller uses a list of hardcoded [USB IDs](/sys/linux/init_vusb_ids.go) that are [patched](/sys/linux/init_vusb.go) into `syz_usb_connect` by syzkaller runtime. One of the ways to make syzkaller target only particular USB drivers is to alter that list. The instructions below describe a hackish way to generate syzkaller USB IDs for all USB drivers enabled in your `.config`.

1. Apply [this](/tools/syz-usbgen/usb_ids.patch) kernel patch.

2. Build and boot the kernel.

3. Connect a USB HID device. In case you're using a `CONFIG_USB_RAW_GADGET=y` kernel, use the
[keyboard emulation program](https://raw.githubusercontent.com/xairy/raw-gadget/master/examples/keyboard.c).

4. Use [syz-usbgen](/tools/syz-usbgen/usbgen.go) script to update [syzkaller descriptions](/sys/linux/init_vusb_ids.go):

    ```
    ./bin/syz-usbgen $KERNEL_LOG ./sys/linux/init_vusb_ids.go
    ```

5. Don't forget to revert the applied patch and rebuild the kernel before doing actual fuzzing.


## Running reproducers on Linux-based boards

It's possible to run syzkaller USB reproducers on a Linux-based board plugged into a physical USB host.

See [Running syzkaller USB reproducers](https://github.com/xairy/raw-gadget/blob/master/docs/syzkaller_reproducers.md) in the Raw Gadget repository for the instructions.
