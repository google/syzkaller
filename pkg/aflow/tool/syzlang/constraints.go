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
    - For platform drivers: Rebind an existing platform device (such as 'pcspkr', 'alarmtimer', or 'serial8250') to
      the target platform driver by writing the target driver name to './sys/bus/platform/devices/<existing_device>/driver_override'
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
- USB Device Emulation (raw-gadget / dummy_hcd):
  * Connect Device: Use 'syz_usb_connect(speed, dev_len, dev, conn)' (or 'syz_usb_connect_ath9k').
    - 'speed': 0x0 (Full), 0x1 (High), 0x2 (Super).
    - 'dev': USB descriptors. Pass complex nested structs using ANY squashing:
      &(0x7f0000000040)=ANY=[@ANYBLOB="120100..."].
    - Asynchronous Driver Probe Rule: Device enumeration runs asynchronously in background kernel threads (hub_wq).
      To prevent race conditions, you MUST insert a sleep delay (e.g. 'nanosleep(&(0x7f0000000300)={0, 50000000}, 0)')
      immediately after 'syz_usb_connect' before calling openat or ioctl on the device node.
  * Disconnect: Use 'syz_usb_disconnect(conn)'.
  * Control Transfer: Use 'syz_usb_control_io(conn, req, res)'.
  * Endpoint I/O: Use 'syz_usb_ep_write(conn, ep, len, data)' or 'syz_usb_ep_read(conn, ep, len, data)'
    (e.g. ep 0x81 IN / 0x02 OUT).
- Network & Wireless (802.11 Wi-Fi, TUN/TAP, Netlink):
  * Packet Injection: Use 'syz_emit_ethernet(len, packet, frags)' to inject raw L2 frames into
    the executor TUN/TAP interface.
  * 802.11 Wi-Fi Injection: Use 'syz_80211_inject_frame(mac, frame, len)' to send 802.11 management/data frames
    to mac80211_hwsim. Always insert nanosleep delays between successive auth, assoc, and probe response frames.
  * 802.11 Ad-Hoc: Use 'syz_80211_join_ibss(ifname, ssid, len, freq)' to join IBSS networks.
  * Generic Netlink Family ID: Use 'syz_genetlink_get_family_id(name, fd)' to look up Netlink IDs
    (e.g. for 'nl80211', 'wireguard', 'team').
  * TCP State Tracking: Use 'syz_extract_tcp_res(res, seq_inc, ack_inc)' to extract TCP sequence/ACK numbers.
- Filesystems, Mounts & Sandbox Bypass:
  * Mount Image: Use 'syz_mount_image(fs, dir, flags, opts, chdir, size, img)'. Preferred method for mounting
    disk images ('ext4', 'btrfs', 'xfs', 'squashfs', 'f2fs', 'erofs', 'fuse'). If 'chdir' is 1, changes executor
    working directory into mount point 'dir'.
  * FUSE Handling: Use 'syz_fuse_handle_req(fd, buf, len, res)' to emulate a FUSE daemon replying to kernel
    requests on '/dev/fuse' ('fd').
  * Sandbox Device Node Opening: Use 'syz_open_dev$char(0xc, major, minor)' or 'syz_open_dev$block(0xb, major, minor)'
    to open device nodes by major/minor numbers, bypassing absolute path sandbox restrictions.
    Use 'syz_open_dev(dev, id, flags)' for paths with '#' markers (e.g. '/dev/tty#').
  * Procfs Opening: Use 'syz_open_procfs(pid, file)' to open '/proc/<pid>/<file>' (or '/proc/self/<file>' if pid==0).
  * Partition Tables: Use 'syz_read_part_table(size, img)' to parse GPT/MBR partition tables on loop devices.
- High-Performance Ring I/O & Block Devices (io_uring & ublk):
  * io_uring: Use 'syz_io_uring_setup', 'syz_io_uring_submit', 'syz_io_uring_complete', and
    'syz_io_uring_modify_offsets' for ring operations.
  * ublk Devices: Use 'syz_ublk_setup_io_uring', 'syz_ublk_add_dev', 'syz_ublk_setup_queues', and
    'syz_ublk_process_io' for userspace block device emulation.
- Virtualization (KVM):
  * Use 'syz_kvm_setup_syzos_vm', 'syz_kvm_setup_cpu', 'syz_kvm_add_vcpu', 'syz_kvm_vgic_v3_setup', and
    'syz_kvm_assert_*' for guest VM setup and assertions.
  * KVM Execution Timeouts & Hangs: Calls to KVM (such as 'ioctl$KVM_RUN' or other $kvm commands) frequently
    time out or hang during guest VM execution, returning CallErrors with
    'Error': 'call execution timed out or hung' (Errno 38).
    When executing KVM programs, the generator should determine whether 'call execution timed out or hung'
    (or 'ioctl$KVM_RUN') is an acceptable error and specify it in 'AcceptableCallErrorsDescription'
    when calling 'code-fixer'.
- BPF & Utility Helpers:
  * BTF ID Lookup: Use 'syz_btf_id_by_name(name)' to obtain BTF IDs for kernel hooks/structs.
  * Process Control: Use 'syz_clone', 'syz_clone3', 'syz_pidfd_open', and 'syz_pkey_set'.`

const TestSeedConstraints = `ENVIRONMENT SETUP & TEST SEED TEMPLATE CONSTRAINTS:
- Entire Setup Prepend: All setup syscalls (such as 'syz_mount_image', 'syz_usb_connect', 'mkdirat',
  or 'openat' for mount points/files) MUST be written by you directly in the generated syzlang program.
  No external base test seeds are prepended for you.
- Subsystem Setup & Precondition Search:
  When targeting complex subsystems (networking, USB, FUSE, storage, bpf, crypto), do NOT guess complex setup
  sequences or raw payload descriptors. Use 'syz-grepper' (with PathPrefix='test') to search Syzkaller's test seeds
  for complete working setup patterns and payload blobs (@ANYBLOB="..."). Additionally, use 'get-corpus-programs'
  on related setup functions—such as direct callers along the target call path, or probe/init functions of
  peer drivers within the same subsystem directory or driver family—to discover existing corpus program
  setup sequences.`

const KVMConstraints = `KVM VIRTUALIZATION AND GUEST CONSTRAINTS (x86/amd64 Focus):
- Syzkaller Description File Locations:
  * Generic/Architecture-Independent KVM Ioctls (e.g. 'openat$kvm', 'ioctl$KVM_CREATE_VM',
    'ioctl$KVM_RUN', 'ioctl$KVM_GET_VCPU_MMAP_SIZE') reside in 'sys/linux/dev_kvm.txt'.
  * Architecture-Specific SYZOS Pseudo-Syscalls for x86/amd64 (e.g. 'syz_kvm_setup_syzos_vm$x86',
    'syz_kvm_add_vcpu$x86') reside in 'sys/linux/dev_kvm_amd64.txt'.
- Sandbox Bypass: You MUST NOT open '/dev/kvm' with generic 'openat'. Always use the specialized variant
  'openat$kvm' to obtain the system KVM fd.
- SYZOS VM & VCPU Setup:
  * Use 'syz_kvm_setup_syzos_vm$x86' to allocate guest memory and load the SYZOS guest library.
  * Use 'syz_kvm_add_vcpu$x86' to initialize the vCPU and define the sequence of guest instructions/commands
    (the SYZOS payload array) that the guest vCPU will execute inside the VM context when 'ioctl$KVM_RUN' is called.
- SYZOS Payload Array Construction (Read 'sys/linux/dev_kvm_amd64.txt'):
  * Purpose: The SYZOS payload array defines the sequence of guest operations (e.g. CPUID queries, MSR reads/writes,
    PIO/MMIO accesses, or nested VMX/SVM hypercalls) executed inside the guest VM to trigger target KVM VM exits
    and guest execution paths in the host kernel.
  * Do NOT guess payload array argument structures. Use 'read-syz-spec' on 'sys/linux/dev_kvm_amd64.txt'
    (starting around line 20) to inspect the exact type definitions:
    1. 'syz_kvm_add_vcpu$x86' accepts 'text' pointing to 'kvm_text$x86'.
    2. 'kvm_text$x86' contains 'text ptr[in, array[syzos_api_call$x86, 1:32]]'.
    3. Each element in the array is an option from the 'syzos_api_call$x86' union,
       defined using the generic 'syzos_api$x86[NUM, PAYLOAD]' template.
- Struct Protection Rules (no_squash):
  * 'syz_kvm_add_vcpu$x86' and key KVM ioctls are marked '(no_squash)'. You MUST NOT squash or replace
    struct fields with generic 'ANY' byte arrays or raw blobs.
- Test Assertion Exclusions (no_generate):
  * Assertions such as 'syz_kvm_assert_syzos_uexit$x86' and 'syz_kvm_assert_syzos_kvm_exit$x86' are marked
    '(no_generate)'. They are unit test verification routines and MUST NOT be included in generated fuzzing programs.
- Unrolled KVM_RUN Execution Resumption Loop:
  * Guest execution yields to Host L0 via 'uexit', 'hlt', or hypervisor exits. You MUST generate multiple
    unrolled 'ioctl$KVM_RUN(r3, AUTO, 0x0)' calls to resume guest execution after each yield/exit step.
- Reference Discovery via Test Seeds and Corpus:
  * Test Seeds: ALWAYS set 'PathPrefix' to 'test' when using 'syz-grepper' to find test seeds in 'sys/linux/test/'.
  * Corpus DB: Use 'get-corpus-programs' targeting KVM entry points (such as 'kvm_vcpu_ioctl' or 'kvm_vm_ioctl')
    to retrieve working examples from the corpus database.
- Target Subsystem to SYZOS Primitive Guidance (x86/amd64):
  * Nested Virtualization ('arch/x86/kvm/vmx/', 'arch/x86/kvm/svm/'): Use 'read-syz-spec' on 'dev_kvm_amd64.txt'
    to inspect '@enable_nested', '@nested_create_vm', '@nested_load_code', '@nested_vmlaunch',
    '@nested_intel_vmwrite_mask', '@nested_amd_vmcb_write_mask', '@nested_vmresume'.
    Search test seeds with PathPrefix='test' and Query='amd64-syz_kvm_nested'.
  * x86 Core & Privileged Ops ('arch/x86/kvm/x86.c', 'mmu/', 'cpuid.c', 'emulate.c', 'virt/kvm/kvm_main.c'): Inspect
    '@cpuid', '@wrmsr', '@rdmsr', '@wr_crn', '@wr_drn', '@in_dx', '@out_dx', '@set_irq_handler' in 'dev_kvm_amd64.txt'.
    Search test seeds with PathPrefix='test' and Query='wrmsr'.
- Simplification Heuristics:
  * When targeting generic shadow MMU or page-track paths, prefer simple non-nested paging configurations first,
    rather than immediately jumping to nested VMX. Nested virtualization introduces extra validation constraints
    that make reaching the target PC harder.
- Anti-Hallucination & Clock Request Guardrails:
  * Do NOT claim KVM execution is blocked by 'KVM_REQ_CLOCK_UPDATE' or 'get_cpu_tsc_khz'. SYZOS guests do not
    initialize pvclock, so kvm_guest_time_update is a non-blocking no-op.
  * To reach KVM I/O bus handlers ('kvm_io_bus_read', 'kvm_io_bus_write'), use guest PIO instructions
    ('@in_dx', '@out_dx'), guest MMIO accesses, or register in-kernel devices ('ioctl$KVM_CREATE_IRQCHIP',
    'ioctl$KVM_CREATE_PIT2').
- KVM Guest Memory (usermem) & VCPU Mmap Rules:
  * 'syz_kvm_setup_syzos_vm$x86': Requires 1024 pages (4MB) of VMA memory for guest RAM.
    Pass: '&(0x7f0000c00000/0x400000)' as the 2nd argument ('usermem').
  * 'syz_kvm_setup_cpu$x86': Requires 24 pages (96KB) of VMA memory.
    Pass: '&(0x7f0000000000/0x18000)' as the 3rd argument ('usermem').
  * 'mmap$KVM_VCPU': Maps the kvm_run structure for a VCPU.
    Pass 1 page VMA: 'mmap$KVM_VCPU(&(0x7f0000009000/0x1000), r4, 0x3, 0x1, r3, 0x0)'`
