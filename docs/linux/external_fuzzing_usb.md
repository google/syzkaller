External USB fuzzing for Linux kernel
=====================================

syzkaller supports fuzzing the Linux kernel USB subsystem from the external USB device side.
Instead of relying on physical hardware (like [Facedancer](https://github.com/usb-tools/Facedancer)-based boards) or VM management software features (like QEMU [usbredir](https://www.spice-space.org/usbredir.html)), syzkaller fuzzes USB fully within a (potentially-virtualized) environment that runs the Linux kernel.

The USB fuzzing support in syzkaller is based on:

1. [Raw Gadget](https://github.com/xairy/raw-gadget) — a kernel module that implements a low-level interface for the Linux USB Gadget subsystem (now in the mainline kernel);
2. [Dummy HCD/UDC](https://github.com/xairy/raw-gadget/tree/master/dummy_hcd) — a kernel module that sets up virtual USB Device and Host controllers that are connected to each other inside the kernel (existed in the mainline kernel for a long time);
3. KCOV changes that allow collecting coverage [from background kernel threads and interrupts](https://docs.kernel.org/dev-tools/kcov.html#remote-coverage-collection) (now in the mainline kernel);
4. syzkaller changes built on top of the other parts; see the [Internals](/docs/linux/external_fuzzing_usb.md#Internals) section.

Besides this documentation page, for details, see:

- [Coverage-Guided USB Fuzzing with Syzkaller](https://docs.google.com/presentation/d/1z-giB9kom17Lk21YEjmceiNUVYeI6yIaG5_gZ3vKC-M/edit?usp=sharing) talk ([video](https://www.youtube.com/watch?v=1MD5JV6LfxA)) from OffensiveCon 2019 (was given while the USB fuzzing support was a work-in-progress, so some details are outdated);

- [Fuzzing USB with Raw Gadget](https://docs.google.com/presentation/d/1sArf2cN5tAOaovlaL3KBPNDjYOk8P6tRrzfkclsbO_c/edit?usp=sharing) talk ([video](https://www.youtube.com/watch?v=AT3PQjKxa_c)) from BSides Munich 2022 (more up-to-date, but less in-depth);

- [External fuzzing of Linux kernel USB drivers with syzkaller](https://docs.google.com/presentation/d/1ba7Au3Gt6dEQAsfZmjUdzjVWHKxE_EdaJGU9WOSF-Ts/edit?usp=sharing) talk (outlines steps for adding new basic USB descriptions).

See [this page](/docs/linux/found_bugs_usb.md) for the list of bugs found in the Linux kernel USB stack so far.


## Setting up

1. Use the kernel version 5.7 or later.

    It's also recommended to backport all kernel patches that touch `drivers/usb/gadget/legacy/raw_gadget.c`, `drivers/usb/gadget/udc/dummy_hcd.c`, and `kernel/kcov.c`;

2. Enable `CONFIG_USB_RAW_GADGET=y` and `CONFIG_USB_DUMMY_HCD=y` in the kernel config.

    Optionally, also enable the config options for the specific USB drivers that you wish to fuzz.

    As an alternative, you can use the [config](/dashboard/config/linux/upstream-usb.config) from the syzbot USB fuzzing instance.
    This config has many USB drivers commonly-used in distro kernels enabled;

3. Build the kernel;

4. Optionally, update syzkaller descriptions by [extracting the USB IDs](#updating-usb-ids).

    This step is recommended if you wish to just rely on the existing syzlang descriptions to fuzz all USB drivers enabled in your kernel config.

    If you plan to add new syzlang descriptions that target a specific USB driver, this step can be skipped;

5. Optionally, [write](#internals) [syzlang](#dealing-with-complicated-descriptors) [descriptions](#handling-post-enumeration-control-requests) for the USB driver you wish to fuzz;

6. Enable `syz_usb_connect`, `syz_usb_disconnect`, `syz_usb_control_io`, `syz_usb_ep_write` and `syz_usb_ep_read` pseudo-syscalls (or any of their specific variants) in the manager config;

7. Set `sandbox` to `none` in the manager config;

8. Pass `dummy_hcd.num=4` (or whichever number you use for `procs`) to the kernel command-line parameters in the manager config;

9. Run syzkaller.

    Make sure that you see both `USBEmulation` and `ExtraCoverage` enabled in the `machine check` section in the log.

    You should also see a decent amount of coverage in `drivers/usb/core/*` after the first few programs get added to the corpus.


## Internals

syzkaller defines 5 main pseudo-syscalls for fuzzing USB drivers (see the [syzlang descriptions](/sys/linux/vusb.txt) and the [C](/executor/common_usb.h) [implementations](/executor/common_usb_linux.h)):

1. `syz_usb_connect` — handles the enumeration process of a new USB device (in simple terms: connects a new USB device; in detail: handles all control requests up until a `SET_CONFIGURATION` request is received);
2. `syz_usb_disconnect` — disconnects a USB device;
3. `syz_usb_control_io` — handles a post-enumeration control request (`IN` or `OUT`);
4. `syz_usb_ep_write` — handles a non-control `IN` request on an endpoint;
5. `syz_usb_ep_read` — handles a non-control `OUT` request on an endpoint.

Additionally, there is the `syz_usb_connect_ath9k` pseudo-syscall targeted to handle a few [post-enumeration control requests](#handling-post-enumeration-control-requests) the `ath9k` driver expects.

The syzlang descriptions for these pseudo-syscalls are targeted at a few different parts of the USB subsystem:

1. The common USB enumeration code is targeted by the generic `syz_usb_connect` variant.

    In addition, this generic variant also briefly touches the enumeration code in various USB drivers: the USB device descriptor fields get [patched](#usb-ids-patching) during the program generation;

2. The code of the class-specific drivers is targeted by `syz_usb_connect$hid`, `syz_usb_connect$cdc_ecm`, and other variants (accompanied by matching `syz_usb_control_io$*` and `syz_usb_ep_read/write$*` pseudo-syscalls).

    The descriptor fields for these `syz_usb_connect` variants are also intended to be [patched](#usb-ids-patching) during the program generation based on the matching rules specific to the driver class (to exercise various driver quirks).
So far, this has only been implemented for the HID ([see](/sys/linux/init_vusb.go) `generateUsbHidDeviceDescriptor`) and the printer ([see](/sys/linux/init_vusb.go) `generateUsbPrinterDeviceDescriptor`) classes;

3. The code of the device-specific drivers is intended to be targeted by more `syz_usb_connect` variants whose descriptors do not get patched and are fully defined in syzlang instead. (However, they can be patched as well for drivers that define quirks.)

    So far, the only such (partial) descriptions have been added for the `ath9k`, `rtl8150`, `sierra_net`, and `lan78xx`  drivers.


## Dealing with complicated descriptors

Many USB drivers expect a fixed USB descriptors structure from the connected USB device.
Writing syzlang descriptions for these drivers is straightforward: just describe the required structures in syzlang.

However, some drivers allow various permutations of the interface/endpoint descriptors (typically the case for class-specific drivers like UVC).

Describing a fixed descriptor structure for such drivers in syzlang would allow passing the driver descriptor checks and efficiently fuzz the post-enumeration communication.
But it would also prevent syzkaller from exploring the various error-checking paths within the driver's enumeration code.
On the other hand, defining a relaxed structure for the descriptors would make syzkaller often fail the driver's enumeration and thus would not allow efficiently fuzzing the post-enumeration communication.

There are two proposed ways to handle such drivers:

1. Writing relaxed descriptions and adding seed programs (aka runtests).

    This works by only defining a single `syz_usb_connect` variant with the relaxed descriptions of the USB descriptors but also adding a [seed program](#seed-programs) (into `sys/linux/test/`) that contains the `syz_usb_connect` pseudo-syscall with the specific fixed values to pass the driver's enumeration checks;

2. Adding two `syz_usb_connect` variants.

    One with relaxed descriptions to explore the error-checking paths; and the other with fixed descriptions to allow fuzzing the post-enumeration communication.


## Handling post-enumeration control requests

Many USB drivers finish their enumeration procedure with the `SET_CONFIGURATION` request.
Following this, these drivers start functioning normally and are ready to accept both control and non-control requests.

However, some USB drivers expect certain control requests to be handled by the device directly following the `SET_CONFIGURATION` request.
Without these requests being handled, these drivers abort their execution and disconnect the device.

There are two proposed ways to handle such drivers:

1. Adding seed programs (aka runtests).

    This works by adding a [seed program](#seed-programs) (into `sys/linux/test/`) that contains both the `syz_usb_connect` pseudo-syscall for the specific driver and a few `syz_usb_control_io` pseudo-sycalls that handle the required control requests.

    This is the currently recommended way of handling such drivers, as it allows syzkaller to permute the expected post-`SET_CONFIGURATION` control requests and thus possibly trigger unexpected driver behavior during their handling.

    See [#6283](https://github.com/google/syzkaller/pull/6283) for a reference implementation of this approach;

2. Modifying the behavior of the `syz_usb_connect` pseudo-syscall.

    An alternative approach is to modify the C implementation of the `syz_usb_connect` pseudo-syscall (or add a similar new pseudo-syscall) to handle the required post-`SET_CONFIGURATION` requests directly from C.

    Right now, this approach is only implemented for the `ath9k` driver via `syz_usb_connect_ath9k`.
Unlike `syz_usb_connect`, `syz_usb_connect_ath9k` also handles the post-`SET_CONFIGURATION` firmware download requests expected by `ath9k`.

    If this approach is to be used for other drivers, the proper implementation should rework and extend `syz_usb_connect_ath9k` instead of adding more similar pseudo-syscalls.
For example, add a new argument to `syz_usb_connect` that allows specifiying (in syzlang) the responses to post-`SET_CONFIGURATION` control requests and which one them is the last one (i.e., the condition for exiting the pseudo-syscall).
And then port the hardcoded responses from the C implementation of `syz_usb_connect_ath9k` into syzlang and extend the functionality based on the specific new encountered cases.

Note: There is also a way to describe unusual pre-`SET_CONFIGURATION` `GET_DESCRIPTOR` requests via the `conn_descs` argument of `syz_usb_connect`, but none of the class/driver-specific descriptions use this feature at the moment.
However, this approach does not allow specifying the order of the responses if there are multiple requests of the same type and also does not allow handling pre-`SET_CONFIGURATION` non-`GET_DESCRIPTOR` requests, as no described drivers required this so far.


## USB IDs patching

Many USB drivers implement various quirks depending of which device is connected.
Such quirks are either defined in the mathing rule table for the driver (a table of `usb_device_id` structures; [see](https://elixir.bootlin.com/linux/v6.16/source/sound/usb/card.c#L1263) e.g. `usb_audio_ids`) or hardcoded in the drivers code (by manually checking e.g. the Vendor and Product IDs against certain values; [see](https://elixir.bootlin.com/linux/v6.16/source/drivers/usb/class/usblp.c#L213) e.g. `quirk_printers`).

To exercise these driver quirks, syzkaller has to provide certain values (aka IDs) within the USB descriptors for the emulated device.
Listing these USB IDs manually in syzlang descriptions is inefficient (there are too many), so syzkaller employs the way of automatically [extracting the IDs](#updating-usb-ids) before building and then [patching them in](/sys/linux/init_vusb.go) during the program generation.

The IDs defined in the driver matching rules can be extracted (and patched in) automatically; see [Updating USB IDs](#updating-usb-ids).

However, the hardcoded IDs need to be specified manually (extacting them automatically is hard, as they are often embedded into the drivers code in non-standard ways).
The proposed approach is to read the driver code to find out the hardcoded IDs and then modify the program generation code to embed them into the appropriate USB decriptors ([see](/sys/linux/init_vusb.go) e.g. `generateUsbPrinterDeviceDescriptor`).


## Updating USB IDs

syzkaller relies on a list of automatically-extracted [USB IDs](/sys/linux/init_vusb_ids.go) that are [patched](/sys/linux/init_vusb.go) into `syz_usb_connect` (for the generic, the HID, and the printer variants) during the program generation.

To update the syzkaller USB IDs based on the USB drivers enabled in your kernel config:

1. Apply [this](/tools/syz-usbgen/usb_ids.patch) kernel patch;

2. Build and boot the kernel;

3. Connect a USB HID device.

    Assuming you have `CONFIG_USB_RAW_GADGET=y` enabled, you can just run the [keyboard emulation program](https://raw.githubusercontent.com/xairy/raw-gadget/master/examples/keyboard.c);

4. Use [syz-usbgen](/tools/syz-usbgen/usbgen.go) to update [sys/linux/init_vusb_ids.go](/sys/linux/init_vusb_ids.go):

    ``` bash
    ./bin/syz-usbgen $KERNEL_LOG ./sys/linux/init_vusb_ids.go
    ```

5. Revert the applied kernel patch and rebuild the kernel before starting syzkaller.


## Seed programs

There are a few [seed programs](/sys/linux/test/) (aka runtests) for the USB pseudo-syscalls (named starting with the `vusb` prefix).

These seed programs serve two purposes:

1. Allow syzkaller to [go](#dealing-with-complicated-descriptors) [deeper](#handling-post-enumeration-control-requests) into the driver code without having to write detailed syzlang descriptions;

2. Allow veryfing the USB fuzzing functionality and catching potential descriptions breaking changes by running the seed programs as runtests:

    ``` bash
    ./bin/syz-manager -config usb-manager.cfg -mode run-tests -tests vusb
    ```

## Limitations

Most of the limitations of the USB fuzzing support in syzkaller stem from the features [missing](https://github.com/xairy/raw-gadget/tree/master?tab=readme-ov-file#limitations) from the Raw Gadget and Dummy HCD/UDC implementations (USB 3, isochronous transfers, etc).

In addition, `syz_usb_connect` only supports devices with a single configuration (but this can be fixed).
This is not a critical limitation, as most kernel drivers are tied to specific interfaces and do not care about the configurations.
However, there are USB devices whose drivers assume the device to have multiple specific configurations.


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
