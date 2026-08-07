// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package syzlang

const SandboxConstraints = `SANDBOX AND FILESYSTEM CONSTRAINTS:
- Sandbox Restrictions: Absolute paths starting with '/' and relative paths starting with '..' are
  strictly forbidden in filenames due to sandboxing. Do NOT attempt to use escaping sequences like
  '\/' or '\.' or path-prefix tricks like './dir/../../file' to bypass this. All paths undergo
  filepath.Clean() during validation, which resolves './dir/../../file' to '../file', causing it to be
  IMMEDIATELY REJECTED. Filenames must be simple CWD-relative paths without '..' (e.g. 'file0' or './file1').
  * Local Pseudo-Filesystem Mount Pattern (ConfigFS, Sysfs, Procfs): To interact with kernel
    pseudo-filesystems, mount them locally in the CWD (e.g. 'mkdirat(AT_FDCWD, "./config", 0777)'
    followed by 'mount(0, "./config", "configfs", 0, 0)' or 'mount(0, "./sys", "sysfs", 0, 0)').
    All subsequent operations (openat, mkdirat, write, symlinkat) must use CWD-relative
    paths starting with './config/' or './sys/'. Absolute paths starting with '/' are forbidden.
  * Symlink Targets in ConfigFS: In 'symlinkat', the target path ('old') is resolved from CWD
    (AT_FDCWD) at creation time. Specify target paths relative to CWD (e.g.
    './config/usb_gadget/g1/functions/midi.usb0') rather than using '..' (e.g. '../../functions/...')
    or absolute paths ('/sys/kernel/config/...'). This avoids '..' and leading '/',
    satisfying both Syzkaller's sandbox validator and the kernel's VFS resolution.
  * Dynamic Device Instantiation & Rebinding via Sysfs: When a driver is unprobed or a device node is missing,
    mount sysfs locally at './sys' or './sys_mnt' and write to attribute files to dynamically instantiate or
    rebind devices without physical hardware:
    - For platform drivers: Rebind an existing platform device (such as 'pcspkr', 'alarmtimer',
      or 'serial8250') to the target platform driver by writing the target driver name to
      './sys/bus/platform/devices/<existing_device>/driver_override'
      and writing the existing device name to './sys/bus/platform/drivers/<target_driver>/bind'.
    - For I2C / PCI drivers: Use sysfs interface attributes (e.g., './sys/class/i2c-dev/i2c-0/device/new_device',
      './sys/bus/pci/drivers/.../bind', './sys/bus/pci/devices/.../driver_override').
- Device & Sysfs access: You MAY NOT open /sys or /dev files with generic 'openat' and absolute paths starting
  with '/' (like '/sys/...' or '/dev/kvm') in filename arguments, as they escape the sandbox.
  * What you CAN do instead:
    1. Always use 'syz-grepper' to check if a specialized syscall variant exists (e.g., 'openat$kvm', 'openat$fuse',
       'openat$ashmem', 'openat$ptmx') for the target device or pseudo-file and use it instead of generic 'openat'.
    2. For /sys access, mount sysfs locally (e.g. at './sys') and use CWD-relative paths ('./sys/...').
    3. If you need to open an arbitrary character or block device, use 'syz_open_dev$char(0xc, major, minor)'
       or 'syz_open_dev$block(0xb, major, minor)' which bypasses sandbox restrictions.
- Device Node & Hardware Probe Boundary Rules:
  - Subsystem & Resource Precondition Dependency Principle:
    Kernel APIs and drivers frequently depend on a multi-stage precondition chain (e.g., mounting a pseudo-fs,
    creating a parent resource handle, or emulating a parent device controller).
    If interacting with a target node or API returns errors (such as ENOENT, ENODEV, or EINVAL), check whether
    a prerequisite setup call or parent resource producer must be executed earlier in the program context.
  - If opening a device node or calling ioctl returns ENODEV (No such device) or ENOTTY:
    * Cause A (Missing Setup in Same Program): You forgot to invoke the emulated hardware setup pseudo-syscall
      (e.g., 'syz_usb_connect', 'syz_mount_image', or virtual interface setup) in the SAME execution program.
      Executions are isolated; hardware connections do NOT persist across executions.
    * Cause B (Unprobed Physical Hardware): The driver requires non-emulated physical PCI hardware or missing hardware
      architecture structures that cannot be probed via sysfs rebinding or pseudo-syscalls.
      CRITICAL: You MUST NOT assume hardware or features are missing based on parametric memory; verify build config
      via 'get-environment' and check sysfs/specs.
      Note that platform drivers under /sys/bus/platform/ can be probed via sysfs driver_override + bind on existing
      platform devices (e.g. 'pcspkr') and are NOT hardware blockers.
      Treat as a terminal hardware blocker only if empirical verification proves the target cannot be probed.
- Built-in Kernel Driver Verification:
  - DO NOT assume a kernel driver is uncompiled or missing (CONFIG_FOO=n) simply because /sys/module/<driver_name>
    returns -ENOENT. Built-in drivers (CONFIG_FOO=y) that export no module parameters omit /sys/module/ entries.
  - Always verify driver build status via the 'get-environment' tool (checking .config), vmlinux symbols, or
    /sys/bus/platform/drivers/ and /sys/bus/pci/drivers/.
- Asynchronous Drivers and Hardware Setup:
  - Emulated hardware connections or interface configurations are transient and exist ONLY for the duration
    of the test program.
  - To test if an emulated/virtual driver is functional, you MUST perform both the hardware setup/connection
    and the device node interaction (e.g., 'openat', 'ioctl') in a single unified program.
    Do NOT separate connection/setup calls and device access calls into separate execute-seed steps.
  - Device connection and initialization (like 'syz_usb_connect') execute asynchronously in background kernel threads.
    To ensure that the asynchronous driver probe finishes before the program exits, you MUST append a sleep/delay call
    (e.g., 'nanosleep(&(0x7f0000000300)={1, 0}, 0)') immediately after the connection pseudo-syscall.
  - Kernel KCOV Coverage Annotation Gaps: Asynchronous driver enumeration and control transfers run in background
    kthreads (e.g., 'hub_wq', 'fsg_main_thread') or softirqs ('dummy_timer') which may lack kernel-side KCOV
    instrumentation.
    Do NOT assume a setup program failed solely because process-level KCOV did not record coverage in
    background threads.
- Predefined Environments & Setup: You MAY NOT write complex initialization sequences or mount
  commands from scratch (e.g., manually mounting a filesystem or crafting USB handshake packets).
  * What you CAN do instead: Use pseudo-syscalls (like 'syz_open_dev', 'syz_mount_image') or find
    existing working setups in test seeds (using 'syz-grepper' with PathPrefix='test') to configure
    complex devices, interfaces, or filesystem mounts.
- CWD Resolution: Relative paths are resolved against the executor's current working directory inside the VM.`

const SyzlangSyntaxConstraints = `SYZLANG SYNTAX AND STRUCTURAL CONSTRAINTS:
- Program Structure: Syzlang programs must contain ONLY system call invocations and variable assignments.
  Assume all types, structs, and resources are already defined.
  Never define custom types, structs, or resources inline.
- Single-line constraint: Multi-line syscall statements are syntax-invalid (cause unexpected eof).
  Each syscall invocation and its variable assignment must reside entirely on a single line.
  Do NOT split a syscall invocation across multiple lines.
- Inline comments: Comments inside syscall statements/arguments are forbidden.
  Comments starting with '#' must only be placed on their own separate lines.
- Arrays vs Buffers: Array arguments MUST be formatted as '[val1, val2]' while Buffer arguments
  MUST be formatted as strings (e.g. "\x00\x01" or 'string').
  Do NOT use array syntax for buffers.
- Struct Fields: Structs MUST contain the exact number of fields specified in their definition.
  Use 'AUTO' if you want to omit fields or let the fuzzer fill them.
- String Literals: Use single quotes ('...') for text, filenames, and device paths.
  Null-terminate C-strings with \x00 (e.g., '/dev/kvm\x00').
- Escaping: The only valid escape sequences inside strings are \x (hex) and \\ (backslash).
  Escaping forward slashes (\/) or dots (\.) causes syntax errors.
- Byte Payloads: Use double quotes ("...") EXCLUSIVELY for raw hexadecimal sequences
  (e.g., "00abcdef"). Using them for normal text will cause decoding errors.
- Pointer Squashing (ANY Union): When a syscall requires a pointer to a complex nested struct
  (such as 'usb_device_descriptor' in 'syz_usb_connect'), do NOT write nested brackets
  '{{ "{{" }}...{{ "}}" }}' or type templates.
  Instead, pass a raw hex string representation of the struct using the built-in 'ANY' union:
  &(0x7f0000000000)=ANY=[@ANYBLOB="<hex_string>"].
  Note that double quotes are required for the hex string inside ANY.
- Resource Usage Rules:
  - Finding Resources: Search for the resource identifier itself (e.g., fd or sock).
    The "resource" keyword is used exactly once at declaration and should not be included in search queries.
  - Resource Producers: Valid producers use the resource as a syscall return type,
    or within a struct field marked (out) or ptr[out, ...].
    Struct fields marked opt or inside unions cannot be producers.
  - Resource Consumers: Valid consumers use the resource as an input argument to a syscall
    or inside a struct field marked (in).
- Preference for Specialized Syscall Variants over Generic Syscalls:
  - When opening a device node, pseudo-file, or interacting with specific subsystems/protocols, ALWAYS prefer
    specialized syscall variants (e.g., 'openat$kvm', 'openat$fuse', 'ioctl$KVM_...', 'socket$netlink') over
    generic base syscalls (e.g., bare 'openat', generic 'ioctl', generic 'socket').
  - Rationale:
    1. Generic 'openat' with absolute paths (e.g. '/dev/kvm') violates sandbox rules, whereas specialized
       variants (e.g., 'openat$kvm') are properly handled.
    2. Specialized variants produce specialized resource handles (e.g., 'fd_kvm', 'fd_fuse') required by
       downstream subsystem ioctls. Generic 'openat' produces a generic 'fd', causing syzlang type check errors
       when passed to specialized ioctls.
  - Use 'syz-grepper' to search for specialized variants (e.g., query 'openat$') whenever targeting specific
    devices or files.
- Go Source Files: Do NOT attempt to read Go source files (e.g. *.go files in prog/ or pkg/)
  to reverse-engineer validation rules or syscall syntax. This consumes tokens and causes goal distraction.
  Consult docs/syscall_descriptions_syntax.md instead using 'read-syz-spec'.
- Syscall Name Verification: Always verify that any specialized syscall variant name you use actually exists
  in the syzkaller specification (using 'syz-grepper' or 'read-syz-spec'). Do not hallucinate variants
  (like 'openat$kvm_param').`

const VMAAndMemoryPointerConstraints = `MEMORY ADDRESS AND VMA TYPE CONSTRAINTS:
- Memory Address Types ('ptr' vs 'vma' / 'vma64'):
  * Data Pointers ('ptr[in, T]', 'ptr[out, T]', 'ptr[inout, T]'):
    - Represent pointers to C structs, arrays, or scalars containing input/output data.
    - Syntax in syzlang programs: Assign data using '&AUTO={...}' or explicit address
      '&(0x7f0000000000)={field1, field2}'.
  * Virtual Memory Areas ('vma' / 'vma64'):
    - Represent unallocated or allocated virtual memory page ranges used for memory mapping (e.g., 'mmap',
      'munmap', 'madvise', 'syz_kvm_setup_syzos_vm', 'prctl$PR_SET_VMA', or struct fields like
      'kvm_userspace_memory_region.addr').
    - Syntax in syzlang programs: MUST be formatted as an address with byte region size WITHOUT data payload assignment:
      '&(0x7f0000xxxxxx/0x<size_in_bytes>)'
    - Example for 'kvm_userspace_memory_region': 'addr' is 'vma64[1:2]'. In program text, write
      'addr=&(0x7f0000800000/0x2000)'.
    - NEVER pass struct initializers '{...}' or data assignments '=...' to a 'vma' parameter.
- Page Alignment Requirement for VMA:
  * Address and size in a 'vma' specification MUST be page-aligned (multiples of 0x1000 / 4096 bytes).
  * Standard allocation examples:
    - 1 page (4KB): '&(0x7f0000009000/0x1000)'
    - 24 pages (96KB): '&(0x7f0000000000/0x18000)'
    - 1024 pages (4MB): '&(0x7f0000c00000/0x400000)'`

const DomainBoundaryConstraints = `TOOL AND SEARCH DOMAIN BOUNDARIES:
- Syzkaller Specification vs Linux Kernel Domain:
  - Syzkaller Specification Domain: Use 'read-syz-spec' and 'syz-grepper' tools EXCLUSIVELY for syzkaller
    specification/metadata files (e.g., '*.txt', '*.txt.const'), test seeds ('test/*'),
    documentation ('docs/*'), and executor C++ header files ('executor/*').
  - Linux Kernel Domain: Use 'codesearch-*' and 'grepper' tools EXCLUSIVELY for Linux kernel source tree files
    ('include/', 'kernel/', 'drivers/', 'fs/', 'net/', 'Documentation/', '*.c', etc.).
- Special Path Distinctions:
  - POSIX / C Headers and VFS Paths: Standard headers starting with 'sys/' (e.g. 'sys/socket.h', 'sys/mount.h')
    and virtual filesystem runtime paths (e.g. '/sys/class/...', '/sys/devices/...') belong to the Linux Kernel
    domain. Use codesearch or grepper for them.
  - Pseudo-Syscalls Definition: Pseudo-syscall definitions starting with 'long syz_*' (e.g. 'syz_usb_connect',
    'syz_mount_image') are implemented in the Syzkaller executor header files under the 'executor/' directory.
- Test Seed Scope & Setup:
  - To search inside test seed files for relevant setup syscalls or device configurations, use 'syz-grepper'
    with PathPrefix='test'. Do NOT filter by filenames via Expression.
  - Test seeds contain syzlang programs establishing preconditions; they do NOT contain C kernel code.`

const PseudoSyscallConstraints = `SYZKALLER PSEUDO-SYSCALLS USAGE & REFERENCE:
- Overview: Pseudo-syscalls (prefixed with 'syz_') are custom executor C functions that emulate hardware devices,
  manage filesystem mounts, bypass sandbox restrictions, and interact with complex kernel subsystems.
  Working syzlang seed examples demonstrating how to use these pseudo-syscalls
  can be located using 'syz-grepper' with PathPrefix='test'.
- General Sandbox Bypass & Path Utility Helpers:
  * Sandbox Device Node Opening: Use 'syz_open_dev$char(0xc, major, minor)' or 'syz_open_dev$block(0xb, major, minor)'
    to open device nodes by major/minor numbers, bypassing absolute path sandbox restrictions.
    Use 'syz_open_dev(dev, id, flags)' for paths with '#' markers (e.g. '/dev/tty#').
  * Procfs Opening: Use 'syz_open_procfs(pid, file)' to open '/proc/<pid>/<file>' (or '/proc/self/<file>' if pid==0).
- Process & Utility Helpers:
  * Process Control: Use 'syz_clone', 'syz_clone3', 'syz_pidfd_open', and 'syz_pkey_set'.
- Subsystem-Specific Emulation (USB, Network/Wi-Fi, Filesystems, FUSE, Virtualization, io_uring, BPF):
  * Do NOT guess pseudo-syscall arguments or rules for complex driver subsystems.
  * You MUST check 'Available Subsystem Skills' in your instructions and read the corresponding subsystem skill
    (e.g., 'skills/usb.md', 'skills/wifi.md', 'skills/fs.md', 'skills/kvm.md', 'skills/io_uring.md', 'skills/bpf.md')
    using 'read-syz-spec' before writing code.`

const TestSeedConstraints = `ENVIRONMENT SETUP & TEST SEED TEMPLATE CONSTRAINTS:
- Entire Setup Prepend: All setup syscalls (such as 'syz_mount_image', 'syz_usb_connect', 'mkdirat',
  or 'openat' for mount points/files) MUST be written by you directly in the generated syzlang program.
  No external base test seeds are prepended for you.
- Subsystem Setup & Precondition Search:
  When targeting complex subsystems (networking, USB, FUSE, storage, bpf, crypto), do NOT guess complex setup
  sequences or raw payload descriptors. Use 'syz-grepper' (with PathPrefix='test') to search Syzkaller's test seeds
  for complete working setup patterns. Copy and adapt those setup sequences directly into your program.
- Blob Placeholders: Test seeds and corpus programs contain large data payloads
  (such as filesystem images or USB device descriptors) represented by placeholders starting
  with "$BLOB_" (e.g. "$BLOB_a1b2c3d4e5f6").
  - You MUST preserve these placeholder strings exactly as-is when copying setup sequences.
  - Do NOT decode, modify, or replace these placeholders with hex or other string contents.
  - The runtime execution engine will automatically restore these placeholders back to their original
    data bytes at runtime.
  - Additionally, use 'get-corpus-programs' on related setup functions—such as direct callers along
    the target call path, or probe/init functions of peer drivers within the same subsystem directory
    or driver family—to discover existing corpus program setup sequences.
  - Subsystem Skills & Specialized Guidance:
    When targeting specific kernel subsystems (such as KVM, networking, USB, BPF, FUSE, etc.),
    check the 'Available Subsystem Skills' listed in your instructions.
    If a relevant skill exists (e.g. 'skills/kvm.md'), read its guidance using 'read-syz-spec'
    before generating or fixing the program.`
