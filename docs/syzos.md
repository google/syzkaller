# SYZOS Technical Documentation

## 1. System Overview

### Concept
SYZOS is not a traditional operating system but an **immutable C library** designed to run as a Guest (L1) within a KVM virtual machine. Its primary purpose is to expose an easy-to-fuzz API to the Host (L0) fuzzer (`syzkaller`), allowing for state-aware interactions that are difficult to achieve with raw instruction fuzzing.

In this architecture, the **Host (syz-executor)** acts as the orchestrator, while the **Guest (SYZOS)** acts as the execution engine for a pre-defined sequence of commands.

### Execution Flow
SYZOS leverages syzkaller's standard execution model, where the fuzzer generates a sequence of syscalls (a `syzlang` program) to be executed by the host executor. For SYZOS, this program constructs the VM and defines the guest's internal logic via pseudo-syscalls.

1.  **VM Creation:** The fuzzer calls standard KVM ioctls (e.g., `openat`, `KVM_CREATE_VM`) to create the VM container.
2.  **Environment Setup (`syz_kvm_setup_syzos_vm`):** This pseudo-syscall automates the complex setup of Guest memory, ensuring the VM has valid code and stack regions.
3.  **VCPU & Program Loading (`syz_kvm_add_vcpu`, see 3.2):**
    * Instead of a bare `KVM_CREATE_VCPU`, the fuzzer calls `syz_kvm_add_vcpu` that creates a new VCPU in the VM and initializes its state.
        * This call takes the **entire sequence of SYZOS commands** as an argument. This sequence effectively becomes the "program" the guest will execute.
    * **Concurrency:** SYZOS supports up to 4 separate VCPUs sharing the same address space, allowing the fuzzer to schedule concurrent guest operations.
4.  **Execution (`KVM_RUN`):** The fuzzer triggers execution via standard `KVM_RUN` calls. The Guest executes its pre-loaded commands step-by-step.
    * **Yielding:** When the Guest needs to perform an action that requires Host intervention (e.g., a transition during Nested Virtualization), it yields to L0 via `UEXIT`.
    * **Resumption:** If the program contains multiple `KVM_RUN` calls, they are used to resume the Guest until the pre-loaded program completes.

### Design Philosophy
* **Logical Mutation:** Instead of fuzzing raw assembly bytes, SYZOS exposes high-level primitives to the fuzzer. The fuzzer mutates the arguments of the SYZOS commands.
* **State Validity:** By implementing setup sequences in C, SYZOS ensures that complex structures like IRQ tables or Page Tables are valid enough to reach deep kernel code paths.

---

## 2. Memory Layout & ABI (Communication Interface)

The Host and Guest communicate via a shared memory protocol. The Host writes commands and arguments into specific physical memory addresses, which the Guest maps and reads.

### Communication Interface
* **Command Channel:** A dedicated memory region where the Host writes the commands and their arguments.
* **Result Channel:** Mechanism for the Guest to report status back to the Host, piggybacked on the `UEXIT` mechanism.
* **Scratch Space:** Mutable memory used by the Guest to generate dynamic code blobs or store temporary data needed for operations like `MSR` writes.

### ARM64 Memory Map
The ARM64 implementation relies on a static physical memory layout to ensure the Host knows exactly where to place data.

| Physical Address | Description | Usage |
| :--- | :--- | :--- |
| `0x08000000` | GIC v3 Distributor | Interaction with Generic Interrupt Controller |
| `0x080a0000` | GIC v3 Redistributor | Per-CPU Interrupt Controller interface |
| `0xdddd0000` - `0xeeee0000` | Read-only / Command Page | Host writes SYZOS commands here. Also used to trigger page faults for `UEXIT` |
| `0xeeee8000` - `0xeeef0000` | Code / Scratch Space | Where SYZOS resides. Also used for generated code (e.g., MSR trampolines) |
| `0xffff1000` | EL1 Stack | Stack space for the SYZOS Guest execution |

### x86 Memory Map
While the exact addresses may vary by implementation, the x86 layout follows similar principles:
* **Guest Code:** Allocated via `KVM_SET_USER_MEMORY_REGION` (typically 1 page).
* **Page Tables:** Setup by the Host to allow virtual-to-physical translation required for long mode.
* **IDT (Interrupt Descriptor Table):** Setup by the Host to handle exceptions within the Guest.

---

## 3. Host-Side Implementation (`syz-executor`)

The Host side is responsible for the heavy lifting of VM initialization. This is achieved through "pseudo-syscalls" - functions implemented in `syz-executor` that look like syscalls to the fuzzer but perform complex setup logic.

### 3.1 VM Initialization: `syz_kvm_setup_syzos_vm()`
This pseudo-syscall creates the VM and prepares the environment.
* **Memory Allocation:** Calls `ioctl(vmfd, KVM_SET_USER_MEMORY_REGION, &memreg)` multiple times to map the Guest physical memory slots (Code, Stack, MMIO).
* **Image Loading:** Copies the compiled SYZOS C library binary into the allocated Guest Code region.

### 3.2 VCPU Initialization: `syz_kvm_add_vcpu()`
This function adds a virtual CPU to the VM and configures its initial state to jump into the SYZOS entry point.
* **Program Loading:** It parses the `syzlang`-generated argument structure, which contains the sequence of SYZOS commands, and copies them into the Guest's Command Page.
* **Context Setup:**
    * **x86:** Sets up SREGS (Segments, Page Tables) and IDT.
    * **ARM64:** Sets PC to the entry point and SP to the stack.

### 3.3 The Handshake Mechanism (`UEXIT`)
The core synchronization primitive is the `UEXIT`.
* **Trigger:** The Guest reads from a specific unmapped or read-only address (e.g., inside `0xdddd0000` on ARM) or executes a specific instruction sequence.
* **Detection:** `KVM_RUN` returns on the Host. The Host may check `kvm_run->exit_reason`.
* **Handling:**
    * If the exit indicates a Page Fault (EPT violation) at the specific `UEXIT` address, the Host treats this as a voluntary yield.
    * The Host reads the exit qualification or register state to retrieve the "return argument" passed by the Guest.

---

## 4. Guest-Side Implementation (SYZOS Library)

### Source Organization & `GUEST_CODE`
SYZOS guest handlers are defined directly in architecture-specific executor headers (e.g., `executor/common_kvm_amd64_syzos.h`).
* **The `GUEST_CODE` Macro:** Functions intended to run inside the guest are marked with `GUEST_CODE` (e.g., `GUEST_CODE static void guest_handle_...`). This instructs the compiler/linker to place these functions in a specific section that `syz-executor` copies into the Guest's physical memory.
* **Header-Based Implementation:** The entire SYZOS codebase is contained within header files included by the executor. This architecture is necessitated by `syz-prog2c`, a tool that converts `syzlang` reproducers into standalone C programs. By concatenating these headers (via `#include` expansion), `syz-prog2c` can produce a single, build-system-independent C source file that compiles anywhere without external dependencies.

### The Dispatch Loop (`guest_main`)
The entry point `guest_main` iterates through the command buffer that was populated by `syz_kvm_add_vcpu`.
* **Command Routing (If/Else Chain):** The routing is strictly implemented as a series of `if/else if` statements rather than a `switch`. The reason for this is that a `switch` statement can be optimized by compilers into a jump table stored in the executable's `.rodata` section. Since the global data sections are not mapped into the Guest address space, accessing a jump table would cause an immediate Page Fault.
* **Argument Parsing:** Commands are cast to specific structures (e.g., `struct api_call_5*`) to access arguments safely.
* **Execution:** The handler performs the logic and the loop advances to the next command in the buffer.

### Core Primitives
* **`SYZOS_API_UEXIT`:** - Triggers a specific exception that the Host recognizes as a "yield". It passes a return value (1 argument) back to the Host to signal success/failure or data.
* **`SYZOS_API_CODE`:** - Executes a raw blob of machine code supplied by the Host. This can be used to emit exact instruction sequences not covered by high-level APIs.

---

## 5. Platform Specifics

### x86 (Intel & AMD)

#### Privileged Operations
SYZOS exposes specific APIs to fuzz privileged x86 instructions:
* **`SYZOS_API_CPUID`:** Executes the `CPUID` instruction.
* **`SYZOS_API_WRMSR` / `SYZOS_API_RDMSR`:** Reads/Writes Model Specific Registers.
* **`SYZOS_API_WR_CRN` / `SYZOS_API_WR_DRN`:** Writes to Control Registers and Debug Registers.
* **`SYZOS_API_IN_DX` / `SYZOS_API_OUT_DX`:** Executes I/O port operations.

#### Nested Virtualization (NV) Engine
SYZOS acts as a lightweight L1 hypervisor to fuzz L2 guests, abstracting the architectural differences between Intel VMX and AMD SVM. It provides a uniform API for the VM lifecycle while offering architecture-specific commands for state mutation.

##### VM Lifecycle & Execution
The following primitives control the nested guest's existence and execution flow:

* **`SYZOS_API_ENABLE_NESTED`:** Enables the virtualization extensions (VMXON on Intel, EFER.SVME on AMD).
* **`SYZOS_API_NESTED_CREATE_VM`:** Initializes the necessary control structures (VMCS for Intel, VMCB for AMD) and sets up Nested Page Tables.
* **`SYZOS_API_NESTED_LOAD_CODE`:** Injects a sequence of instructions into the L2 guest's memory, defining what code the nested machine will execute.
* **`SYZOS_API_NESTED_VMLAUNCH`:** Performs the initial VM Entry, transferring control to the L2 guest.
* **`SYZOS_API_NESTED_VMRESUME`:** Resumes execution of the L2 guest after it has exited back to L1.

##### State Mutation (Architecture Specific)
To stress the host's handling of invalid or edge-case states, SYZOS allows direct mutation of the hardware control structures. This is done by applying the "set/unset/flip" mask logic: `new_val = (old_val & ~unset_mask) | set_mask ^ flip_mask`.
The SYZOS commands are **`SYZOS_API_NESTED_INTEL_VMWRITE_MASK`** (mutates the VMCS fields on Intel) and **`SYZOS_API_NESTED_AMD_VMCB_WRITE_MASK`** (VMCB on AMD).

---

### ARM64

#### Device Emulation
A significant portion of ARM64 KVM code is device emulation. SYZOS provides specialized APIs to fuzz these complex interactions.
* **GICv3 & ITS:**
    * **`SYZOS_API_IRQ_SETUP`:** Sets up the VGICv3 distributor and installs the guest IRQ table.
    * **`SYZOS_API_ITS_SETUP`:** Allocates translation tables and configures the Interrupt Translation Service (ITS) base.
    * **`SYZOS_API_ITS_SEND_CMD`:** Injects structured GIC commands (e.g., `MAPD`, `MOVI`) into the command queue.

#### Hypervisor Interface
SYZOS targets the boundary between the Guest and EL2/Firmware.
* **Hypercalls:**
    * **`SYZOS_API_HVC`:** Executes `hvc #0` with fuzzer-controlled parameters in registers `x0-x5`.
    * **`SYZOS_API_SMC`:** Executes `smc #0` (Secure Monitor Call) with parameters in `x0-x5`.

---

## 6. Developer Guide: How to Add a New Command

This guide details the process of adding a new SYZOS command, using `SYZOS_API_NESTED_AMD_VMCB_WRITE_MASK` as a reference case.

### Step 1: Define API ID and Handler Prototype
Modify the architecture-specific executor header (e.g., `executor/common_kvm_amd64_syzos.h`) to register the new command.

1.  **Add the Enum ID:** Add a new entry to the `syzos_api_id` enum.
    ```c
    typedef enum {
        // ...
        SYZOS_API_NESTED_AMD_VMCB_WRITE_MASK = 380, // New ID
        SYZOS_API_STOP,
    } syzos_api_id;
    ```
2.  **Declare the Handler:** Add a forward declaration using the `GUEST_CODE` macro.
    ```c
    GUEST_CODE static void guest_handle_nested_amd_vmcb_write_mask(struct api_call_5* cmd, uint64 cpu_id);
    ```

Note: make sure to choose the optimal api_call_N structure that exactly matches the number of arguments required by your new primitive (e.g., use struct api_call_2 for a command needing two arguments). If no arguments are required, omit the `cmd` parameter altogether. If the guest code does not access VMCB/VMCS, omit the `cpu_id` parameter.

### Step 2: Implement Guest Logic and Dispatch
In the same file (or corresponding source), implement the guest logic.

1.  **Add Dispatch Case:** Update `guest_main`.
    ```c
    } else if (call == SYZOS_API_NESTED_AMD_VMCB_WRITE_MASK) {
        guest_handle_nested_amd_vmcb_write_mask((struct api_call_5*)cmd, cpu);
    }
    ```
2.  **Implement Handler:** Write the function logic. Strict guest-safe code restrictions apply.
    ```c
    GUEST_CODE static noinline void
    guest_handle_nested_amd_vmcb_write_mask(struct api_call_5* cmd, uint64 cpu_id)
    {
        if (get_cpu_vendor() != CPU_VENDOR_AMD) return;
        // ... parse args and perform logic ...
        vmcb_write64(vmcb_addr, offset, new_value);
    }
    ```

### Step 3: Define syzlang Description
Expose the new command to `syzkaller` in the description file (e.g., `sys/linux/dev_kvm_amd64.txt`).

1.  **Define Structures:** Define any necessary constants or structures.
    ```
    syzos_api_nested_amd_vmcb_write_mask {
	vm_id		syzos_api_vm_id
	offset		vmcb_offset
	set_mask	int64
	unset_mask	int64
	flip_mask	int64
    }
    ```

2.  **Map Command ID:** Add the command to the `syzos_api_call` union. **Crucial:** The ID (e.g., `380`) must match the enum in the C header.
    ```
    syzos_api_call$x86 [
        nested_amd_vmcb_write_mask  syzos_api$x86[380, syzos_api_nested_amd_vmcb_write_mask]
    ] [varlen]
    ```

---

## 7. Validation & Regression Testing

The system includes a regression testing framework located in `sys/linux/test/`. New commands must include a test case to verify they trigger the expected Hypervisor behavior.

### Test File Structure
Tests are `syzlang` programs with special assertions.
* **Header:** Requires metadata, e.g., `# requires: arch=amd64 -threaded`.
* **Setup:** Standard boilerplate creates a VM and enters SYZOS.
* **Logic:** The test configures the guest to perform a specific action (e.g., executing `HLT` in a nested L2 guest).

### Assertions
Tests use specialized pseudo-syscalls to assert the VM's exit state:
* **`syz_kvm_assert_syzos_uexit$x86(fd, code)`:** Asserts that the guest voluntarily yielded with a specific `UEXIT` code (e.g., `0xe2e20001`).
* **`syz_kvm_assert_syzos_kvm_exit$x86(fd, exit_reason)`:** Asserts that the guest triggered a standard KVM exit (e.g., `0x5` for `KVM_EXIT_HLT`) that was trapped by L0.
