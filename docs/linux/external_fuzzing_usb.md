External USB fuzzing for Linux kernel
=====================================

syzkaller supports fuzzing the Linux kernel USB subsystem from the external side.
Instead of relying on external hardware (like [Facedancer](https://github.com/usb-tools/Facedancer)-based boards) or VM management software features (like QEMU [usbredir](https://www.spice-space.org/usbredir.html)), syzkaller fuzzes USB fully within a (potentially-virtualized) environment that runs the Linux kernel.

The USB fuzzing support in syzkaller is based on:

1. [Raw Gadget](https://github.com/xairy/raw-gadget) — kernel module that implements a low-level interface for the Linux USB Gadget subsystem (now in the mainline kernel);
2. [Dummy HCD/UDC](https://github.com/xairy/raw-gadget/tree/master/dummy_hcd) — kernel module that sets up virtual USB Device and Host controllers that are connected to each other inside the kernel (existed in the mainline kernel for a long time);
3. KCOV changes that allow collecting coverage [from background kernel threads and interrupts](https://docs.kernel.org/dev-tools/kcov.html#remote-coverage-collection) (now in the mainline kernel);
4. syzkaller changes built on top of the other parts; see the [Internals](/docs/linux/external_fuzzing_usb.md#Internals) section.

Besides this documentation page, for details, see:

- [Coverage-Guided USB Fuzzing with Syzkaller](https://docs.google.com/presentation/d/1z-giB9kom17Lk21YEjmceiNUVYeI6yIaG5_gZ3vKC-M/edit?usp=sharing) talk ([video](https://www.youtube.com/watch?v=1MD5JV6LfxA)) from OffensiveCon 2019 (the talk was given while the USB fuzzing support was a work-in-progress, so some details are outdated);

- [Fuzzing USB with Raw Gadget](https://docs.google.com/presentation/d/1sArf2cN5tAOaovlaL3KBPNDjYOk8P6tRrzfkclsbO_c/edit?usp=sharing) talk ([video](https://www.youtube.com/watch?v=AT3PQjKxa_c)) from BSides Munich 2022 (more up-to-date, but less in-depth).

See [this page](/docs/linux/found_bugs_usb.md) for the list of bugs found in the Linux kernel USB stack so far.


## Internals

syzkaller defines 6 pseudo-syscalls for emulating USB devices for fuzzing (see the [syzlang descriptions](/sys/linux/vusb.txt) and the [C](/executor/common_usb.h) [implementations](/executor/common_usb_linux.h)):

1. `syz_usb_connect` — handles the enumeration process of a new USB device (in simple terms: connects a new USB device; in detail: handles all requests to the control endpoint until a `SET_CONFIGURATION` request is received);
2. `syz_usb_connect_ath9k` — flavor of `syz_usb_connect` for connecting an `ath9k` USB device.
Not implemented as a `$`variant of `syz_usb_connect`, as `ath9k` expects a compatible device to immediately handle the firmware download requests after the enumeration (after the `SET_CONFIGURATION` request);
3. `syz_usb_disconnect` — disconnects a USB device;
4. `syz_usb_control_io` — handles a post-enumeration control request (`IN` or `OUT`);
5. `syz_usb_ep_write` — handles a non-control `IN` request on an endpoint;
6. `syz_usb_ep_read` — handles a non-control `OUT` request on an endpoint.

The syzlang descriptions for these pseudo-syscalls are targeted at a few different layers:

1. The common USB enumeration code is targeted by the generic `syz_usb_connect` variant.
In addition, this generic variant also briefly touches the enumeration code in various USB drivers: the USB device descriptor fields get [patched](/sys/linux/init_vusb.go) during the program generation;

2. The code of the class-specific drivers is targeted by `syz_usb_connect$hid`, `syz_usb_connect$cdc_ecm`, and other variants (accompanied by matching `syz_usb_control_io$*` and `syz_usb_ep_read/write$*` pseudo-syscalls).
The descriptor fields for these `syz_usb_connect` variants are also intended to be patched during the program generation based on the driver class (to exercise various driver quirks), but so far, this has only been implemented for the HID class;

3. The code of the device-specific drivers is intended to be targeted by more `syz_usb_connect` variants whose descriptors do not get patched and are fully defined in syzlang instead.
So far, the only such (partial) descriptions have been added for the `ath9k` driver (`syz_usb_connect_ath9k` and `syz_usb_ep_write$ath9k_ep*`).


## Setting up

1. Use the kernel version 5.7 or later.

    It's also recommended to backport all kernel patches that touch `drivers/usb/gadget/legacy/raw_gadget.c`, `drivers/usb/gadget/udc/dummy_hcd.c`, and `kernel/kcov.c`;

2. Enable `CONFIG_USB_RAW_GADGET=y` and `CONFIG_USB_DUMMY_HCD=y` in the kernel config.

    Optionally, also enable the config options for the specific USB drivers that you wish to fuzz.

    As an alternative, you can use the [config](/dashboard/config/linux/upstream-usb.config) from the syzbot USB fuzzing instance.
    This config has the options for many USB drivers commonly-used in distro kernels enabled;

3. Build the kernel;

4. Optionally, update syzkaller descriptions by [extracting the USB IDs](/docs/linux/external_fuzzing_usb.md#updating-syzkaller-usb-ids).

    This step is recommended if you wish to just rely on the existing syzlang descriptions to fuzz all USB drivers enabled in your kernel config.

    If you plan to add new syzlang descriptions that target a specific USB driver, this step can be skipped;

5. Optionally, write syzlang descriptions for the USB driver you wish to fuzz;

6. Enable `syz_usb_connect`, `syz_usb_disconnect`, `syz_usb_control_io`, `syz_usb_ep_write` and `syz_usb_ep_read` pseudo-syscalls (or any of their specific variants) in the manager config;

7. Set `sandbox` to `none` in the manager config;

8. Pass `dummy_hcd.num=4` (or whichever number you use for `procs`) to the kernel command-line parameters in the manager config;

9. Run syzkaller.

    Make sure that you see both `USBEmulation` and `ExtraCoverage` enabled in the `machine check` section in the log.

    You should also see a decent amount of coverage in `drivers/usb/core/*` after the first few programs get added to the corpus.


## Limitations

Most of the limitations of the USB fuzzing support in syzkaller stem from the features [missing](https://github.com/xairy/raw-gadget/tree/master?tab=readme-ov-file#limitations) from the Raw Gadget and Dummy HCD/UDC implementations (USB 3, isochronous transfers, etc).

In addition, `syz_usb_connect` only supports devices with a single configuration (but this can be fixed).
This is not a critical limitation, as most kernel drivers are tied to specific interfaces and do not care about the configurations.
However, there are USB devices whose drivers assume the device to have multiple specific configurations.


## Runtests

There are a few [runtests](/sys/linux/test/) for the USB pseudo-syscalls.
They are named starting with the `vusb` prefix and can be run as:

``` bash
./bin/syz-manager -config usb-manager.cfg -mode run-tests -tests vusb
```


## Updating syzkaller USB IDs

syzkaller uses a list of hardcoded [USB IDs](/sys/linux/init_vusb_ids.go) that are [patched](/sys/linux/init_vusb.go) into `syz_usb_connect` (for the generic and the HID variants) during the program generation.

To update the syzkaller USB IDs to match the USB drivers enabled in your kernel config:

1. Apply [this](/tools/syz-usbgen/usb_ids.patch) kernel patch;

2. Build and boot the kernel;

3. Connect a USB HID device.

    Assuming you have `CONFIG_USB_RAW_GADGET=y` enabled, you can just run the [keyboard emulation program](https://raw.githubusercontent.com/xairy/raw-gadget/master/examples/keyboard.c);

4. Use [syz-usbgen](/tools/syz-usbgen/usbgen.go) script to update [sys/linux/init_vusb_ids.go](/sys/linux/init_vusb_ids.go):

    ``` bash
    ./bin/syz-usbgen $KERNEL_LOG ./sys/linux/init_vusb_ids.go
    ```

5. Revert the applied kernel patch and rebuild the kernel before starting syzkaller.


## Things to improve

The core support for USB fuzzing is in place, but there's still space for improvement:

1. Remove the device from `usb_devices` in `syz_usb_disconnect` and don't call `lookup_usb_index` multiple times within `syz_usb_connect`.
Currently, this causes some reproducers to have the `repeat` flag set when it's not required;

2. Add descriptions for more relevant USB classes and drivers and resolve TODOs from [sys/linux/vusb.txt](/sys/linux/vusb.txt);

3. Implement a proper way for dynamically extracting relevant USB ids from the kernel (a related [discussion](https://www.spinics.net/lists/linux-usb/msg187915.html));

4. Add a mode for standalone fuzzing of physical USB hosts (from a Linux-based board with a UDC).
This includes: a. Making sure that the current way `syz_usb_connect` handles the enumeration works properly with different OSes (there are some [differences](https://github.com/RoganDawes/LOGITacker/blob/USB_host_enum/fingerprint_os.md#derive-the-os-from-the-fingerprint));
b. Using USB requests coming from the host as a signal (like coverage) to enable "signal-driven" fuzzing;
c. Making UDC driver name configurable for `syz-execprog` and `syz-prog2c`;

5. Generate syzkaller programs from a `usbmon` trace produced by real USB devices (this should make syzkaller go significantly deeper into the USB drivers code).


## Running reproducers on Linux-based boards

It is possible to run the reproducers for USB bugs generated by syzkaller on a Linux-based board plugged into a physical USB host.

See [Running syzkaller USB reproducers](https://github.com/xairy/raw-gadget/blob/master/docs/syzkaller_reproducers.md) in the Raw Gadget repository for the instructions.
