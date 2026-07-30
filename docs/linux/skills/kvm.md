---
name: kvm
description: KVM Virtualization and Guest Constraints (x86/amd64 Focus)
---

# KVM Virtualization and Guest Constraints (x86/amd64 Focus)

- Syzkaller Description File Locations:
  * Generic/Architecture-Independent KVM Ioctls (e.g. 'openat$kvm', 'ioctl$KVM_CREATE_VM',
    'ioctl$KVM_RUN', 'ioctl$KVM_GET_VCPU_MMAP_SIZE') reside in 'dev_kvm.txt'.
  * Architecture-Specific SYZOS Pseudo-Syscalls for x86/amd64 (e.g. 'syz_kvm_setup_syzos_vm$x86',
    'syz_kvm_add_vcpu$x86') reside in 'dev_kvm_amd64.txt'.
- Sandbox Bypass: You MUST NOT open '/dev/kvm' with generic 'openat'. Always use the specialized variant
  'openat$kvm' to obtain the system KVM fd.
- SYZOS VM & VCPU Setup:
  * Use 'syz_kvm_setup_syzos_vm$x86' to allocate guest memory and load the SYZOS guest library.
  * Use 'syz_kvm_add_vcpu$x86' to initialize the vCPU and define the sequence of guest instructions/commands
    (the SYZOS payload array) that the guest vCPU will execute inside the VM context when 'ioctl$KVM_RUN' is called.
- Strict KVM ioctl Sequence Order (CRITICAL INSTRUCTION):
  When configuring a VM and vCPUs, you MUST follow this exact sequence:
  1) Create VM ('ioctl$KVM_CREATE_VM')
  2) Set VM-wide capabilities and CPUID leaves ('ioctl$KVM_SET_CPUID2', 'ioctl$KVM_SET_CAP')
  3) Create vCPU ('syz_kvm_add_vcpu$x86'), passing the guest execution code payload as its 'text' argument
  4) Set vCPU state/registers or MSRs ('ioctl$KVM_SET_MSRS', 'ioctl$KVM_SET_LAPIC', 'ioctl$KVM_SET_REGS')
  5) Execute VM run loop ('ioctl$KVM_RUN').
  Calling 'ioctl$KVM_SET_CPUID2' after adding a vCPU invalidates vCPU segment/register setups and causes
  'ioctl$KVM_RUN' to abort with 'vmx_unhandleable_emulation_required'.
- Hyper-V VP Index & Multi-vCPU Target Path Testing:
  When targeting Hyper-V TLB flush, IPI, or sparse vCPU bank set checks (e.g., 'hv_is_vp_in_sparse_set',
  'valid_bit_nr > 0'), do NOT declare the target unreachable on a single-vCPU VM. You can set the vCPU's Hyper-V
  VP index to any value (e.g., 'vp_index = 64') via 'ioctl$KVM_SET_MSRS' targeting 'HV_X64_MSR_VP_INDEX'
  (0x40000002). This allows testing high VP indices without creating 64 physical vCPUs.
- SYZOS Payload Array Construction (Read 'dev_kvm_amd64.txt'):
  * Purpose: The SYZOS payload array defines the sequence of guest operations (e.g. CPUID queries, MSR reads/writes,
    PIO/MMIO accesses, or nested VMX/SVM hypercalls) executed inside the guest VM to trigger target KVM VM exits
    and guest execution paths in the host kernel.
  * Do NOT guess payload array argument structures. Use 'read-syz-spec' on 'dev_kvm_amd64.txt'
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
  * Test Seeds: ALWAYS set 'PathPrefix' to 'test' when using 'syz-grepper' to find test seeds in 'test/'.
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
    Pass 1 page VMA: 'mmap$KVM_VCPU(&(0x7f0000009000/0x1000), r4, 0x3, 0x1, r3, 0x0)'
