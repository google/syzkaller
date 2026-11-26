// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#ifndef EXECUTOR_COMMON_KVM_AMD64_SYZOS_H
#define EXECUTOR_COMMON_KVM_AMD64_SYZOS_H

// This file provides guest code running inside the AMD64 KVM.

#include <linux/kvm.h>
#include <stdbool.h>

#include "common_kvm_syzos.h"
#include "kvm.h"

// There are no particular rules to assign numbers here, but changing them will
// result in losing some existing reproducers. Therefore, we try to leave spaces
// between unrelated IDs.
// Remember these constants must match those in sys/linux/dev_kvm_amd64.txt.
typedef enum {
	SYZOS_API_UEXIT = 0,
	SYZOS_API_CODE = 10,
	SYZOS_API_CPUID = 100,
	SYZOS_API_WRMSR = 101,
	SYZOS_API_RDMSR = 102,
	SYZOS_API_WR_CRN = 103,
	SYZOS_API_WR_DRN = 104,
	SYZOS_API_IN_DX = 105,
	SYZOS_API_OUT_DX = 106,
	SYZOS_API_MEMWRITE = 110,
	SYZOS_API_SET_IRQ_HANDLER = 200,
	SYZOS_API_ENABLE_NESTED = 300,
	SYZOS_API_NESTED_CREATE_VM = 301,
	SYZOS_API_NESTED_LOAD_CODE = 302,
	SYZOS_API_NESTED_VMLAUNCH = 303,
	SYZOS_API_NESTED_VMRESUME = 304,
	SYZOS_API_NESTED_LOAD_SYZOS = 310,
	SYZOS_API_NESTED_SET_STATE_PAGES = 320,
	SYZOS_API_NESTED_INTEL_VMWRITE_MASK = 340,
	SYZOS_API_NESTED_INTEL_MSR_LIST_ADD = 341,
	SYZOS_API_NESTED_INTEL_INVEPT = 342,
	SYZOS_API_NESTED_INTEL_INVVPID = 343,
	SYZOS_API_NESTED_INTEL_EPTP_LIST_SET = 344,
	SYZOS_API_NESTED_INTEL_VMFUNC = 345,
	SYZOS_API_NESTED_INTEL_VMREAD = 346,
	SYZOS_API_NESTED_INTEL_VMWRITE = 347,
	SYZOS_API_NESTED_INTEL_EVMCS_ENABLE = 348,
	SYZOS_API_NESTED_INTEL_EVMCS_WRITE_MASK = 349,
	SYZOS_API_NESTED_AMD_VMCB_WRITE_MASK = 380,
	SYZOS_API_NESTED_AMD_INVLPGA = 381,
	SYZOS_API_NESTED_AMD_STGI = 382,
	SYZOS_API_NESTED_AMD_CLGI = 383,
	SYZOS_API_NESTED_AMD_INJECT_EVENT = 384,
	SYZOS_API_NESTED_AMD_SET_INTERCEPT = 385,
	SYZOS_API_NESTED_AMD_VMLOAD = 386,
	SYZOS_API_NESTED_AMD_VMSAVE = 387,
	SYZOS_API_STOP, // Must be the last one
} syzos_api_id;

// Pages referenced by the nested VMCS/VMCB that SYZOS_API_NESTED_SET_STATE_PAGES can relocate.
// MSRPM and IOPM are supported on both Intel and AMD, the rest are Intel-only.
typedef enum {
	NESTED_PAGE_APIC_ACCESS = 0, // Intel: APIC-access page.
	NESTED_PAGE_VAPIC = 10, // Intel: virtual-APIC page.
	NESTED_PAGE_MSRPM = 20, // Intel: MSR bitmap; AMD: MSR permission map.
	NESTED_PAGE_IOPM = 30, // Intel: I/O bitmaps A and B; AMD: I/O permission map.
	NESTED_PAGE_POSTED_INTR = 40, // Intel: posted-interrupt descriptor.
	NESTED_PAGE_PML = 50, // Intel: page-modification log.
	NESTED_PAGE_EPTP_LIST = 60, // Intel: VMFUNC EPTP list page.
	NESTED_PAGE_VMREAD_BITMAP = 70, // Intel: VMREAD bitmap.
	NESTED_PAGE_VMWRITE_BITMAP = 80, // Intel: VMWRITE bitmap.
	NESTED_PAGE_SHADOW_VMCS = 90, // Intel: shadow VMCS (VMCS link pointer).
} nested_page_type;

typedef enum {
	NESTED_EVMCS_FLAG_NONE = 0,
	NESTED_EVMCS_FLAG_ENABLE = 1 << 0,
	NESTED_EVMCS_FLAG_NESTED_FLUSH = 1 << 1,
} nested_evmcs_flags;

// Non-VMCS Hyper-V fields mutated by SYZOS_API_NESTED_INTEL_EVMCS_WRITE_MASK.
typedef enum {
	NESTED_EVMCS_FIELD_REVISION_ID = 0,
	NESTED_EVMCS_FIELD_ABORT = 1,
	NESTED_EVMCS_FIELD_HV_CLEAN_FIELDS = 2,
	NESTED_EVMCS_FIELD_HV_SYNTHETIC_CONTROLS = 3,
	NESTED_EVMCS_FIELD_HV_ENLIGHTENMENTS_CONTROL = 4,
	NESTED_EVMCS_FIELD_HV_VP_ID = 5,
	NESTED_EVMCS_FIELD_HV_VM_ID = 6,
	NESTED_EVMCS_FIELD_PARTITION_ASSIST_PAGE = 7,
	NESTED_EVMCS_FIELD_VP_ASSIST_ENLIGHTEN_VMENTRY = 8,
	NESTED_EVMCS_FIELD_VP_ASSIST_CURRENT_NESTED_VMCS = 9,
	NESTED_EVMCS_FIELD_VP_ASSIST_NESTED_CONTROL = 10,
	NESTED_EVMCS_FIELD_PA_TLB_LOCK_COUNT = 11,
} nested_evmcs_field;

struct api_call_uexit {
	struct api_call_header header;
	uint64 exit_code;
};

struct api_call_code {
	struct api_call_header header;
	uint8 insns[];
};

struct api_call_nested_load_code {
	struct api_call_header header;
	uint64 vm_id;
	uint8 insns[];
};

struct api_call_nested_load_syzos {
	struct api_call_header header;
	uint64 vm_id;
	uint64 unused_pages;
	uint8 program[];
};

struct api_call_cpuid {
	struct api_call_header header;
	uint32 eax;
	uint32 ecx;
};

struct api_call_memwrite {
	struct api_call_header header;
	uint64 base_addr;
	uint64 offset;
	uint64 value;
	uint64 len;
};

// This struct must match the push/pop order in nested_vm_exit_handler_intel_asm().
struct l2_guest_regs {
	uint64 rax, rbx, rcx, rdx, rsi, rdi, rbp;
	uint64 r8, r9, r10, r11, r12, r13, r14, r15;
};

struct hv_nested_enlightenments_control {
	union {
		uint32 as_uint32;
		struct {
			uint32 directhypercall : 1;
			uint32 reserved : 31;
		};
	} features;
	union {
		uint32 as_uint32;
		struct {
			uint32 inter_partition_comm : 1;
			uint32 reserved : 31;
		};
	} hypercall_controls;
};

struct hv_vp_assist_page {
	uint32 apic_assist;
	uint32 reserved1;
	uint32 vtl_entry_reason;
	uint32 vtl_reserved;
	uint64 vtl_ret_x64rax;
	uint64 vtl_ret_x64rcx;
	struct hv_nested_enlightenments_control nested_control;
	uint8 enlighten_vmentry;
	uint8 reserved2[7];
	uint64 current_nested_vmcs;
	uint8 synthetic_time_unhalted_timer_expired;
	uint8 reserved3[7];
	uint8 virtualization_fault_information[40];
	uint8 reserved4[8];
	uint8 intercept_message[256];
	uint8 vtl_ret_actions[256];
} __attribute__((packed));

struct hv_enlightened_vmcs {
	uint32 revision_id;
	uint32 abort;
	uint16 host_es_selector;
	uint16 host_cs_selector;
	uint16 host_ss_selector;
	uint16 host_ds_selector;
	uint16 host_fs_selector;
	uint16 host_gs_selector;
	uint16 host_tr_selector;
	uint16 padding16_1;
	uint64 host_ia32_pat;
	uint64 host_ia32_efer;
	uint64 host_cr0;
	uint64 host_cr3;
	uint64 host_cr4;
	uint64 host_ia32_sysenter_esp;
	uint64 host_ia32_sysenter_eip;
	uint64 host_rip;
	uint32 host_ia32_sysenter_cs;
	uint32 pin_based_vm_exec_control;
	uint32 vm_exit_controls;
	uint32 secondary_vm_exec_control;
	uint64 io_bitmap_a;
	uint64 io_bitmap_b;
	uint64 msr_bitmap;
	uint16 guest_es_selector;
	uint16 guest_cs_selector;
	uint16 guest_ss_selector;
	uint16 guest_ds_selector;
	uint16 guest_fs_selector;
	uint16 guest_gs_selector;
	uint16 guest_ldtr_selector;
	uint16 guest_tr_selector;
	uint32 guest_es_limit;
	uint32 guest_cs_limit;
	uint32 guest_ss_limit;
	uint32 guest_ds_limit;
	uint32 guest_fs_limit;
	uint32 guest_gs_limit;
	uint32 guest_ldtr_limit;
	uint32 guest_tr_limit;
	uint32 guest_gdtr_limit;
	uint32 guest_idtr_limit;
	uint32 guest_es_ar_bytes;
	uint32 guest_cs_ar_bytes;
	uint32 guest_ss_ar_bytes;
	uint32 guest_ds_ar_bytes;
	uint32 guest_fs_ar_bytes;
	uint32 guest_gs_ar_bytes;
	uint32 guest_ldtr_ar_bytes;
	uint32 guest_tr_ar_bytes;
	uint64 guest_es_base;
	uint64 guest_cs_base;
	uint64 guest_ss_base;
	uint64 guest_ds_base;
	uint64 guest_fs_base;
	uint64 guest_gs_base;
	uint64 guest_ldtr_base;
	uint64 guest_tr_base;
	uint64 guest_gdtr_base;
	uint64 guest_idtr_base;
	uint64 padding64_1[3];
	uint64 vm_exit_msr_store_addr;
	uint64 vm_exit_msr_load_addr;
	uint64 vm_entry_msr_load_addr;
	uint64 cr3_target_value0;
	uint64 cr3_target_value1;
	uint64 cr3_target_value2;
	uint64 cr3_target_value3;
	uint32 page_fault_error_code_mask;
	uint32 page_fault_error_code_match;
	uint32 cr3_target_count;
	uint32 vm_exit_msr_store_count;
	uint32 vm_exit_msr_load_count;
	uint32 vm_entry_msr_load_count;
	uint64 tsc_offset;
	uint64 virtual_apic_page_addr;
	uint64 vmcs_link_pointer;
	uint64 guest_ia32_debugctl;
	uint64 guest_ia32_pat;
	uint64 guest_ia32_efer;
	uint64 guest_pdptr0;
	uint64 guest_pdptr1;
	uint64 guest_pdptr2;
	uint64 guest_pdptr3;
	uint64 guest_pending_dbg_exceptions;
	uint64 guest_sysenter_esp;
	uint64 guest_sysenter_eip;
	uint32 guest_activity_state;
	uint32 guest_sysenter_cs;
	uint64 cr0_guest_host_mask;
	uint64 cr4_guest_host_mask;
	uint64 cr0_read_shadow;
	uint64 cr4_read_shadow;
	uint64 guest_cr0;
	uint64 guest_cr3;
	uint64 guest_cr4;
	uint64 guest_dr7;
	uint64 host_fs_base;
	uint64 host_gs_base;
	uint64 host_tr_base;
	uint64 host_gdtr_base;
	uint64 host_idtr_base;
	uint64 host_rsp;
	uint64 ept_pointer;
	uint16 virtual_processor_id;
	uint16 padding16_2[3];
	uint64 padding64_2[5];
	uint64 guest_physical_address;
	uint32 vm_instruction_error;
	uint32 vm_exit_reason;
	uint32 vm_exit_intr_info;
	uint32 vm_exit_intr_error_code;
	uint32 idt_vectoring_info_field;
	uint32 idt_vectoring_error_code;
	uint32 vm_exit_instruction_len;
	uint32 vmx_instruction_info;
	uint64 exit_qualification;
	uint64 exit_io_instruction_ecx;
	uint64 exit_io_instruction_esi;
	uint64 exit_io_instruction_edi;
	uint64 exit_io_instruction_eip;
	uint64 guest_linear_address;
	uint64 guest_rsp;
	uint64 guest_rflags;
	uint32 guest_interruptibility_info;
	uint32 cpu_based_vm_exec_control;
	uint32 exception_bitmap;
	uint32 vm_entry_controls;
	uint32 vm_entry_intr_info_field;
	uint32 vm_entry_exception_error_code;
	uint32 vm_entry_instruction_len;
	uint32 tpr_threshold;
	uint64 guest_rip;
	uint32 hv_clean_fields;
	uint32 padding32_1;
	uint32 hv_synthetic_controls;
	union {
		uint32 as_uint32;
		struct {
			uint32 nested_flush_hypercall : 1;
			uint32 msr_bitmap : 1;
			uint32 reserved : 30;
		};
	} hv_enlightenments_control;
	uint32 hv_vp_id;
	uint32 padding32_2;
	uint64 hv_vm_id;
	uint64 partition_assist_page;
	uint64 padding64_4[4];
	uint64 guest_bndcfgs;
	uint64 guest_ia32_perf_global_ctrl;
	uint64 guest_ia32_s_cet;
	uint64 guest_ssp;
	uint64 guest_ia32_int_ssp_table_addr;
	uint64 guest_ia32_lbr_ctl;
	uint64 padding64_5[2];
	uint64 xss_exit_bitmap;
	uint64 encls_exiting_bitmap;
	uint64 host_ia32_perf_global_ctrl;
	uint64 tsc_multiplier;
	uint64 host_ia32_s_cet;
	uint64 host_ssp;
	uint64 host_ia32_int_ssp_table_addr;
	uint64 padding64_6;
} __attribute__((packed));

// AMD64-specific flags for mem_region.
#define MEM_REGION_FLAG_GPA0 (1 << 5)
#define MEM_REGION_FLAG_REMAINING (1 << 7)

struct syzos_boot_args {
	uint32 region_count;
	uint32 reserved;
	struct mem_region regions[];
};

struct syzos_globals {
	uint64 alloc_offset;
	uint64 total_size;
	uint64 text_sizes[KVM_MAX_VCPU];
	struct l2_guest_regs l2_ctx[KVM_MAX_VCPU][KVM_MAX_L2_VMS];
	uint64 active_vm_id[KVM_MAX_VCPU];
	uint64 vendor;
	uint8 evmcs_enabled[KVM_MAX_VCPU][KVM_MAX_L2_VMS];
	uint8 hv_vp_assist_enabled[KVM_MAX_VCPU];
	// 1-based VM index (vm_id + 1) currently active in hv_vp_assist_page, or 0 if none.
	uint8 active_evmcs_vm[KVM_MAX_VCPU];
};

#ifdef __cplusplus
extern "C" {
#endif
// These three are called from raw inline assembly (`call guest_uexit` etc.),
// which is invisible to the compiler's call graph. A plain `static` definition
// can end up assigned to a different LTO partition than its asm caller and never
// get linked in, even with __attribute__((used)), which only forces the
// definition to be emitted, not to be resolvable from another partition's
// object file. They're kept non-static so they always get external linkage
// instead. They can't be `inline` either: GUEST_CODE places them in a fixed
// "guest" section that gets copied wholesale into VM guest memory, and GCC's
// vague/COMDAT linkage for inline functions conflicts with that fixed section
// placement. The executor and each generated C reproducer are built as a single
// translation unit, so there's no ODR risk from the external linkage. clang-tidy's
// misc-definitions-in-headers is silenced explicitly on each definition below.
GUEST_CODE void guest_uexit(uint64 exit_code);
GUEST_CODE void nested_vm_exit_handler_intel(struct l2_guest_regs* regs);
GUEST_CODE void nested_vm_exit_handler_amd(uint64 exit_reason, struct l2_guest_regs* regs);
#ifdef __cplusplus
}
#endif
GUEST_CODE static void guest_fatal(uint64 exit_code) __attribute__((noreturn));
GUEST_CODE static uint64 api_call_min_size(uint64 call_id);
GUEST_CODE static void guest_execute_code(uint8* insns, uint64 size);
GUEST_CODE static void guest_handle_cpuid(uint32 eax, uint32 ecx);
GUEST_CODE static void guest_handle_wrmsr(uint64 reg, uint64 val);
GUEST_CODE static void guest_handle_rdmsr(uint64 reg);
GUEST_CODE static void guest_handle_wr_crn(struct api_call_2* cmd);
GUEST_CODE static void guest_handle_wr_drn(struct api_call_2* cmd);
GUEST_CODE static void guest_handle_in_dx(struct api_call_2* cmd);
GUEST_CODE static void guest_handle_out_dx(struct api_call_3* cmd);
GUEST_CODE static void guest_handle_memwrite(struct api_call_memwrite* cmd);
GUEST_CODE static void guest_handle_set_irq_handler(struct api_call_2* cmd);
GUEST_CODE static void guest_handle_enable_nested(struct api_call_1* cmd, uint64 cpu_id);
GUEST_CODE static void guest_handle_nested_create_vm(struct api_call_1* cmd, uint64 cpu_id);
GUEST_CODE static void guest_handle_nested_load_code(struct api_call_nested_load_code* cmd, uint64 cpu_id);
GUEST_CODE static void guest_handle_nested_load_syzos(struct api_call_nested_load_syzos* cmd, uint64 cpu_id);
GUEST_CODE static void guest_handle_nested_set_state_pages(struct api_call_3* cmd, uint64 cpu_id);
GUEST_CODE static void guest_handle_nested_vmlaunch(struct api_call_1* cmd, uint64 cpu_id);
GUEST_CODE static void guest_handle_nested_vmresume(struct api_call_1* cmd, uint64 cpu_id);
GUEST_CODE static void guest_handle_nested_intel_vmwrite_mask(struct api_call_5* cmd, uint64 cpu_id);
GUEST_CODE static void guest_handle_nested_intel_msr_list_add(struct api_call_4* cmd, uint64 cpu_id);
GUEST_CODE static void guest_handle_nested_intel_invept(struct api_call_2* cmd);
GUEST_CODE static void guest_handle_nested_intel_invvpid(struct api_call_3* cmd);
GUEST_CODE static void guest_handle_nested_intel_eptp_list_set(struct api_call_3* cmd, uint64 cpu_id);
GUEST_CODE static void guest_handle_nested_intel_vmfunc(struct api_call_2* cmd);
GUEST_CODE static void guest_handle_nested_intel_vmread(struct api_call_1* cmd);
GUEST_CODE static void guest_handle_nested_intel_vmwrite(struct api_call_2* cmd);
GUEST_CODE static void guest_handle_nested_intel_evmcs_enable(struct api_call_2* cmd, uint64 cpu_id);
GUEST_CODE static void guest_handle_nested_intel_evmcs_write_mask(struct api_call_5* cmd, uint64 cpu_id);
GUEST_CODE static void guest_handle_nested_amd_vmcb_write_mask(struct api_call_5* cmd, uint64 cpu_id);
GUEST_CODE static void guest_handle_nested_amd_invlpga(struct api_call_2* cmd, uint64 cpu_id);
GUEST_CODE static void guest_handle_nested_amd_stgi();
GUEST_CODE static void guest_handle_nested_amd_clgi();
GUEST_CODE static void guest_handle_nested_amd_inject_event(struct api_call_5* cmd, uint64 cpu_id);
GUEST_CODE static void guest_handle_nested_amd_set_intercept(struct api_call_4* cmd, uint64 cpu_id);
GUEST_CODE static void guest_handle_nested_amd_vmload(struct api_call_1* cmd, uint64 cpu_id);
GUEST_CODE static void guest_handle_nested_amd_vmsave(struct api_call_1* cmd, uint64 cpu_id);

typedef enum {
	UEXIT_END = (uint64)-1,
	UEXIT_IRQ = (uint64)-2,
	UEXIT_ASSERT = (uint64)-3,
	UEXIT_INVALID_MAIN = (uint64)-4,
} uexit_code;

typedef enum {
	CPU_VENDOR_UNKNOWN = 0,
	CPU_VENDOR_INTEL,
	CPU_VENDOR_AMD,
} cpu_vendor_id;

// Exit code reported for a CPU exception that SYZOS cannot recover from, with the vector in the
// low byte.
#define UEXIT_EXCEPTION(vector) (0xe2ec0000ull | (vector))

__attribute__((naked)) GUEST_CODE static void dummy_null_handler()
{
	asm("iretq");
}

// Size of each entry point in exception_stubs.
#define EXCEPTION_STUB_SIZE 16

// Entry points for CPU exceptions (vectors 0-31) that cannot be resumed with a plain iretq: for
// faults iretq would re-execute the faulting instruction forever, and for exceptions that push an
// error code it would return with a corrupted stack frame. Each EXCEPTION_STUB_SIZE-byte entry
// pushes its vector, so the IDT entry for vector N points to exception_stubs + N *
// EXCEPTION_STUB_SIZE. The common part reports UEXIT_EXCEPTION(vector) to the host every time the
// vCPU is resumed, like guest_fatal() does, and never returns. The error code, if any, is ignored.
__attribute__((naked, aligned(EXCEPTION_STUB_SIZE))) GUEST_CODE static void exception_stubs()
{
	asm volatile(R"(
	    .irp vector, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31
	    .p2align 4
	    pushq $\vector
	    jmp 1f
	    .endr
	1:
	    popq %rbx
	    movl $0xe2ec0000, %eax
	    orq %rax, %rbx
	    // The CPU aligns RSP to 16 bytes before pushing the exception frame, so RSP is only
	    // 16-byte aligned here if an error code was pushed. Align it for the call below, this code
	    // never returns to the interrupted context anyway.
	    andq $-16, %rsp
	2:
	    movq %rbx, %rdi
	    call guest_uexit
	    jmp 2b
	)");
}

// Default IDT handler for a vector. #DB, NMI, #BP, #OF and external interrupts can be resumed with
// iretq, all other CPU exceptions are fatal.
static always_inline uint64 syzos_default_idt_handler(uint64 vector)
{
	volatile uint64 v = vector;
	if (v >= 32 || v == 1 || v == 2 || v == 3 || v == 4)
		return executor_fn_guest_addr(dummy_null_handler);
	return executor_fn_guest_addr(exception_stubs) + v * EXCEPTION_STUB_SIZE;
}

__attribute__((naked)) GUEST_CODE static void uexit_irq_handler()
{
	asm volatile(R"(
	    // Save RBP (used to preserve RSP across alignment) and all caller-saved GPRs, since
	    // guest_uexit() follows the System V AMD64 ABI and iretq returns to interrupted code.
	    pushq %rbp
	    pushq %rax
	    pushq %rcx
	    pushq %rdx
	    pushq %rsi
	    pushq %rdi
	    pushq %r8
	    pushq %r9
	    pushq %r10
	    pushq %r11

	    // Ensure 16-byte stack alignment before calling guest_uexit(): the CPU aligns RSP
	    // before pushing the 5-qword interrupt frame (leaving 16n+8 on entry), and the 10 pushes
	    // above keep it misaligned by 8 bytes.
	    movq %rsp, %rbp
	    andq $-16, %rsp

	    // Call guest_uexit(UEXIT_IRQ).
	    movq $-2, %rdi
	    call guest_uexit

	    movq %rbp, %rsp
	    popq %r11
	    popq %r10
	    popq %r9
	    popq %r8
	    popq %rdi
	    popq %rsi
	    popq %rdx
	    popq %rcx
	    popq %rax
	    popq %rbp
	    iretq
	)");
}

// Main guest function that performs necessary setup and passes the control to the user-provided
// payload.
// The inner loop uses a complex if-statement, because Clang is eager to insert a jump table into
// a switch statement.

// TODO(glider): executor/style_test.go insists that single-line compound statements should not
// be used e.g. in the following case:
//   if (call == SYZOS_API_UEXIT) {
//     struct api_call_uexit* ucmd = (struct api_call_uexit*)cmd;
//     guest_uexit(ucmd->exit_code);
//   } else if (call == SYZOS_API_WR_CRN) {
//     guest_handle_wr_crn((struct api_call_2*)cmd);  // Style check fails here
//   }
// , i.e. when the braces are consistent with the rest of the code, even despite this violates the
// Google C++ style guide.
// We add single-line comments to justify having the compound statements below.
__attribute__((used))
GUEST_CODE static void
guest_main(uint64 cpu)
{
	volatile struct syzos_globals* globals = (volatile struct syzos_globals*)X86_SYZOS_ADDR_GLOBALS;
	uint64 size = globals->text_sizes[cpu];
	uint64 addr = X86_SYZOS_ADDR_USER_CODE + cpu * KVM_PAGE_SIZE;

	while (size >= sizeof(struct api_call_header)) {
		struct api_call_header* cmd = (struct api_call_header*)addr;
		volatile uint64 call = cmd->call;
		// A command must at least hold its header and the fixed arguments of the call: a
		// zero-sized command would be executed forever, and the handlers would read the arguments
		// of a truncated one from past its end.
		// Do not return: the host may resume the vCPU, and there is nowhere to return to.
		if ((call >= SYZOS_API_STOP) || (cmd->size > size) ||
		    (cmd->size < api_call_min_size(call)))
			guest_fatal(UEXIT_INVALID_MAIN);
		if (call == SYZOS_API_UEXIT) {
			// Issue a user exit.
			struct api_call_uexit* ucmd = (struct api_call_uexit*)cmd;
			guest_uexit(ucmd->exit_code);
		} else if (call == SYZOS_API_CODE) {
			// Execute an instruction blob.
			struct api_call_code* ccmd = (struct api_call_code*)cmd;
			guest_execute_code(ccmd->insns, cmd->size - sizeof(struct api_call_header));
		} else if (call == SYZOS_API_CPUID) {
			// Issue CPUID.
			struct api_call_cpuid* ccmd = (struct api_call_cpuid*)cmd;
			guest_handle_cpuid(ccmd->eax, ccmd->ecx);
		} else if (call == SYZOS_API_WRMSR) {
			// Write an MSR register.
			struct api_call_2* ccmd = (struct api_call_2*)cmd;
			guest_handle_wrmsr(ccmd->args[0], ccmd->args[1]);
		} else if (call == SYZOS_API_RDMSR) {
			// Read an MSR register.
			struct api_call_1* ccmd = (struct api_call_1*)cmd;
			guest_handle_rdmsr(ccmd->arg);
		} else if (call == SYZOS_API_WR_CRN) {
			// Write value to a control register.
			guest_handle_wr_crn((struct api_call_2*)cmd);
		} else if (call == SYZOS_API_WR_DRN) {
			// Write value to a debug register.
			guest_handle_wr_drn((struct api_call_2*)cmd);
		} else if (call == SYZOS_API_IN_DX) {
			// Read data from an I/O port.
			guest_handle_in_dx((struct api_call_2*)cmd);
		} else if (call == SYZOS_API_OUT_DX) {
			// Write data to an I/O port.
			guest_handle_out_dx((struct api_call_3*)cmd);
		} else if (call == SYZOS_API_MEMWRITE) {
			// Write data to a guest memory address.
			guest_handle_memwrite((struct api_call_memwrite*)cmd);
		} else if (call == SYZOS_API_SET_IRQ_HANDLER) {
			// Set the handler for a particular IRQ.
			guest_handle_set_irq_handler((struct api_call_2*)cmd);
		} else if (call == SYZOS_API_ENABLE_NESTED) {
			// Enable nested virtualization.
			guest_handle_enable_nested((struct api_call_1*)cmd, cpu);
		} else if (call == SYZOS_API_NESTED_CREATE_VM) {
			// Create a nested VM.
			guest_handle_nested_create_vm((struct api_call_1*)cmd, cpu);
		} else if (call == SYZOS_API_NESTED_LOAD_CODE) {
			// Load code into the nested VM.
			guest_handle_nested_load_code((struct api_call_nested_load_code*)cmd, cpu);
		} else if (call == SYZOS_API_NESTED_LOAD_SYZOS) {
			// Load SYZOS into the nested VM.
			guest_handle_nested_load_syzos((struct api_call_nested_load_syzos*)cmd, cpu);
		} else if (call == SYZOS_API_NESTED_SET_STATE_PAGES) {
			// Mutate nested state pages (APIC access, vAPIC, MSRPM, IOPM, PI desc, PML).
			guest_handle_nested_set_state_pages((struct api_call_3*)cmd, cpu);
		} else if (call == SYZOS_API_NESTED_VMLAUNCH) {
			// Launch the nested VM.
			guest_handle_nested_vmlaunch((struct api_call_1*)cmd, cpu);
		} else if (call == SYZOS_API_NESTED_VMRESUME) {
			// Resume a nested VM.
			guest_handle_nested_vmresume((struct api_call_1*)cmd, cpu);
		} else if (call == SYZOS_API_NESTED_INTEL_VMWRITE_MASK) {
			// Write to a VMCS field using masks.
			guest_handle_nested_intel_vmwrite_mask((struct api_call_5*)cmd, cpu);
		} else if (call == SYZOS_API_NESTED_INTEL_MSR_LIST_ADD) {
			// Append an entry to one of the VMX MSR load/store lists.
			guest_handle_nested_intel_msr_list_add((struct api_call_4*)cmd, cpu);
		} else if (call == SYZOS_API_NESTED_INTEL_INVEPT) {
			// Invalidate the mappings derived from EPT.
			guest_handle_nested_intel_invept((struct api_call_2*)cmd);
		} else if (call == SYZOS_API_NESTED_INTEL_INVVPID) {
			// Invalidate the mappings tagged with a VPID.
			guest_handle_nested_intel_invvpid((struct api_call_3*)cmd);
		} else if (call == SYZOS_API_NESTED_INTEL_EPTP_LIST_SET) {
			// Set a VMFUNC EPTP list entry and enable EPTP switching.
			guest_handle_nested_intel_eptp_list_set((struct api_call_3*)cmd, cpu);
		} else if (call == SYZOS_API_NESTED_INTEL_VMFUNC) {
			// Execute VMFUNC.
			guest_handle_nested_intel_vmfunc((struct api_call_2*)cmd);
		} else if (call == SYZOS_API_NESTED_INTEL_VMREAD) {
			// Execute VMREAD.
			guest_handle_nested_intel_vmread((struct api_call_1*)cmd);
		} else if (call == SYZOS_API_NESTED_INTEL_VMWRITE) {
			// Execute VMWRITE.
			guest_handle_nested_intel_vmwrite((struct api_call_2*)cmd);
		} else if (call == SYZOS_API_NESTED_INTEL_EVMCS_ENABLE) {
			// Enable Hyper-V eVMCS (and optionally L2 direct TLB flush) for a nested VM.
			guest_handle_nested_intel_evmcs_enable((struct api_call_2*)cmd, cpu);
		} else if (call == SYZOS_API_NESTED_INTEL_EVMCS_WRITE_MASK) {
			// Write to a Hyper-V eVMCS or VP assist field using masks.
			guest_handle_nested_intel_evmcs_write_mask((struct api_call_5*)cmd, cpu);
		} else if (call == SYZOS_API_NESTED_AMD_VMCB_WRITE_MASK) {
			// Write to a VMCB field using masks.
			guest_handle_nested_amd_vmcb_write_mask((struct api_call_5*)cmd, cpu);
		} else if (call == SYZOS_API_NESTED_AMD_INVLPGA) {
			// Invalidate TLB mappings for the specified address/ASID.
			guest_handle_nested_amd_invlpga((struct api_call_2*)cmd, cpu);
		} else if (call == SYZOS_API_NESTED_AMD_STGI) {
			// Set Global Interrupt Flag (Enable Interrupts).
			guest_handle_nested_amd_stgi();
		} else if (call == SYZOS_API_NESTED_AMD_CLGI) {
			// Clear Global Interrupt Flag (Disable Interrupts, including NMI).
			guest_handle_nested_amd_clgi();
		} else if (call == SYZOS_API_NESTED_AMD_INJECT_EVENT) {
			// Inject an event (IRQ/Exception) into the L2 guest via VMCB.
			guest_handle_nested_amd_inject_event((struct api_call_5*)cmd, cpu);
		} else if (call == SYZOS_API_NESTED_AMD_SET_INTERCEPT) {
			// Set/Clear specific intercept bits in the VMCB.
			guest_handle_nested_amd_set_intercept((struct api_call_4*)cmd, cpu);
		} else if (call == SYZOS_API_NESTED_AMD_VMLOAD) {
			// Execute VMLOAD to load state from VMCB.
			guest_handle_nested_amd_vmload((struct api_call_1*)cmd, cpu);
		} else if (call == SYZOS_API_NESTED_AMD_VMSAVE) {
			// Execute VMSAVE to save state to VMCB.
			guest_handle_nested_amd_vmsave((struct api_call_1*)cmd, cpu);
		}
		addr += cmd->size;
		size -= cmd->size;
	};
	guest_uexit(UEXIT_END);
}

// Return the minimum size of a command: the header plus the fixed-size arguments of the call.
// This must match the descriptions of the calls in sys/linux/dev_kvm_amd64.txt.
GUEST_CODE static noinline uint64 api_call_min_size(uint64 call_id)
{
	// Prevent the compiler from generating a switch table.
	volatile uint64 call = call_id;
	if (call == SYZOS_API_UEXIT)
		return sizeof(struct api_call_uexit);
	if (call == SYZOS_API_CPUID)
		return sizeof(struct api_call_cpuid);
	if (call == SYZOS_API_MEMWRITE)
		return sizeof(struct api_call_memwrite);
	if (call == SYZOS_API_NESTED_LOAD_CODE)
		return __builtin_offsetof(struct api_call_nested_load_code, insns);
	if (call == SYZOS_API_NESTED_LOAD_SYZOS)
		return __builtin_offsetof(struct api_call_nested_load_syzos, program);
	if ((call == SYZOS_API_RDMSR) || (call == SYZOS_API_ENABLE_NESTED) ||
	    (call == SYZOS_API_NESTED_CREATE_VM) || (call == SYZOS_API_NESTED_VMLAUNCH) ||
	    (call == SYZOS_API_NESTED_VMRESUME) || (call == SYZOS_API_NESTED_INTEL_VMREAD) ||
	    (call == SYZOS_API_NESTED_AMD_VMLOAD) || (call == SYZOS_API_NESTED_AMD_VMSAVE))
		return sizeof(struct api_call_1);
	if ((call == SYZOS_API_WRMSR) || (call == SYZOS_API_WR_CRN) || (call == SYZOS_API_WR_DRN) ||
	    (call == SYZOS_API_IN_DX) || (call == SYZOS_API_SET_IRQ_HANDLER) ||
	    (call == SYZOS_API_NESTED_INTEL_INVEPT) || (call == SYZOS_API_NESTED_INTEL_VMFUNC) ||
	    (call == SYZOS_API_NESTED_INTEL_VMWRITE) ||
	    (call == SYZOS_API_NESTED_INTEL_EVMCS_ENABLE) ||
	    (call == SYZOS_API_NESTED_AMD_INVLPGA))
		return sizeof(struct api_call_2);
	if ((call == SYZOS_API_OUT_DX) || (call == SYZOS_API_NESTED_SET_STATE_PAGES) ||
	    (call == SYZOS_API_NESTED_INTEL_INVVPID) || (call == SYZOS_API_NESTED_INTEL_EPTP_LIST_SET))
		return sizeof(struct api_call_3);
	if ((call == SYZOS_API_NESTED_INTEL_MSR_LIST_ADD) || (call == SYZOS_API_NESTED_AMD_SET_INTERCEPT))
		return sizeof(struct api_call_4);
	if ((call == SYZOS_API_NESTED_INTEL_VMWRITE_MASK) ||
	    (call == SYZOS_API_NESTED_INTEL_EVMCS_WRITE_MASK) ||
	    (call == SYZOS_API_NESTED_AMD_VMCB_WRITE_MASK) ||
	    (call == SYZOS_API_NESTED_AMD_INJECT_EVENT))
		return sizeof(struct api_call_5);
	// SYZOS_API_CODE, SYZOS_API_NESTED_AMD_STGI and SYZOS_API_NESTED_AMD_CLGI have no fixed
	// arguments.
	return sizeof(struct api_call_header);
}

GUEST_CODE static noinline void guest_execute_code(uint8* insns, uint64 size)
{
	volatile void (*fn)() = (volatile void (*)())insns;
	fn();
}

// Perform a userspace exit that can be handled by the host.
// The host returns from ioctl(KVM_RUN) with kvm_run.exit_reason=KVM_EXIT_MMIO,
// and can handle the call depending on the data passed as exit code.

// Called from inline asm; see the forward declaration above for why this is non-static.
__attribute__((used))
GUEST_CODE noinline void
// NOLINTNEXTLINE(misc-definitions-in-headers)
guest_uexit(uint64 exit_code)
{
	// Force exit_code into RAX using inline asm constraints ("a").
	// We write to X86_SYZOS_ADDR_UEXIT (0x40100).
	// This allows the L1 hypervisor to reliably read RAX during an EPT violation.
	volatile uint64* ptr = (volatile uint64*)X86_SYZOS_ADDR_UEXIT;
	// Pin ptr to RDX so the store uses the 3-byte `movq %rax, (%rdx)` encoding
	// assumed when advancing L2 RIP in nested_vm_exit_handler_{intel,amd}().
	asm volatile("movq %0, (%1)" ::"a"(exit_code), "d"(ptr) : "memory");
}

// Report an unrecoverable error to the host and never return. The host may resume the vCPU after
// guest_uexit(), so report the same exit code again every time instead of continuing with broken
// state.
GUEST_CODE static noinline __attribute__((noreturn)) void guest_fatal(uint64 exit_code)
{
	for (;;)
		guest_uexit(exit_code);
}

GUEST_CODE static noinline void guest_handle_cpuid(uint32 eax, uint32 ecx)
{
	asm volatile(
	    "cpuid\n"
	    : // Currently ignore outputs
	    : "a"(eax), "c"(ecx)
	    : "rbx", "rdx");
}

GUEST_CODE static noinline void wrmsr(uint64 reg, uint64 val)
{
	asm volatile(
	    "wrmsr"
	    :
	    : "c"(reg),
	      "a"((uint32)val),
	      "d"((uint32)(val >> 32))
	    : "memory");
}

// Write val into an MSR register reg.
GUEST_CODE static noinline void guest_handle_wrmsr(uint64 reg, uint64 val)
{
	wrmsr(reg, val);
}

GUEST_CODE static noinline uint64 rdmsr(uint64 msr_id)
{
	uint32 low = 0, high = 0; // nolint
	// The RDMSR instruction takes the MSR address in ecx.
	// It puts the lower 32 bits of the MSR value into eax, and the upper.
	// 32 bits of the MSR value into edx.
	asm volatile("rdmsr" : "=a"(low), "=d"(high) : "c"(msr_id));
	return ((uint64)high << 32) | low;
}

// Read an MSR register, ignore the result.
GUEST_CODE static noinline void guest_handle_rdmsr(uint64 reg)
{
	(void)rdmsr(reg);
}

// Read IA32_PERF_GLOBAL_CTRL if it exists, return 0 otherwise.
// KVM only exposes the MSR if the guest PMU version (CPUID.0AH:EAX[7:0]) is at least 2,
// e.g. it is absent if the host has no PMU, and reading it would cause a #GP.
GUEST_CODE static noinline uint64 read_perf_global_ctrl(void)
{
	// If leaf 0xA is above the maximum basic leaf, CPUID returns the data of the
	// highest basic leaf instead, so check the maximum leaf first.
	uint32 eax = 0, ecx = 0;
	asm volatile("cpuid" : "+a"(eax), "+c"(ecx) : : "ebx", "edx");
	if (eax < 0xa)
		return 0;
	eax = 0xa;
	ecx = 0;
	asm volatile("cpuid" : "+a"(eax), "+c"(ecx) : : "ebx", "edx");
	if ((eax & 0xff) < 2)
		return 0;
	return rdmsr(X86_MSR_CORE_PERF_GLOBAL_CTRL);
}

// Write to CRn control register.
GUEST_CODE static noinline void guest_handle_wr_crn(struct api_call_2* cmd)
{
	uint64 value = cmd->args[1];
	// Prevent the compiler from generating a switch table.
	volatile uint64 reg = cmd->args[0];
	if (reg == 0) {
		// Move value to CR0.
		asm volatile("movq %0, %%cr0" ::"r"(value) : "memory");
		return;
	}
	if (reg == 2) {
		// Move value to CR2.
		asm volatile("movq %0, %%cr2" ::"r"(value) : "memory");
		return;
	}
	if (reg == 3) {
		// Move value to CR3.
		asm volatile("movq %0, %%cr3" ::"r"(value) : "memory");
		return;
	}
	if (reg == 4) {
		// Move value to CR4.
		asm volatile("movq %0, %%cr4" ::"r"(value) : "memory");
		return;
	}
	if (reg == 8) {
		// Move value to CR8 (TPR - Task Priority Register).
		asm volatile("movq %0, %%cr8" ::"r"(value) : "memory");
		return;
	}
}

// Write to DRn debug register.
GUEST_CODE static noinline void guest_handle_wr_drn(struct api_call_2* cmd)
{
	uint64 value = cmd->args[1];
	volatile uint64 reg = cmd->args[0];
	if (reg == 0) {
		asm volatile("movq %0, %%dr0" ::"r"(value) : "memory");
		return;
	}
	if (reg == 1) {
		asm volatile("movq %0, %%dr1" ::"r"(value) : "memory");
		return;
	}
	if (reg == 2) {
		asm volatile("movq %0, %%dr2" ::"r"(value) : "memory");
		return;
	}
	if (reg == 3) {
		asm volatile("movq %0, %%dr3" ::"r"(value) : "memory");
		return;
	}
	if (reg == 4) {
		asm volatile("movq %0, %%dr4" ::"r"(value) : "memory");
		return;
	}
	if (reg == 5) {
		asm volatile("movq %0, %%dr5" ::"r"(value) : "memory");
		return;
	}
	if (reg == 6) {
		asm volatile("movq %0, %%dr6" ::"r"(value) : "memory");
		return;
	}
	if (reg == 7) {
		asm volatile("movq %0, %%dr7" ::"r"(value) : "memory");
		return;
	}
}

// Read data from an I/O port, should result in KVM_EXIT_IO.
GUEST_CODE static noinline void guest_handle_in_dx(struct api_call_2* cmd)
{
	uint16 port = cmd->args[0];
	volatile int size = cmd->args[1];

	if (size == 1) {
		uint8 unused;
		// Reads 1 byte from the port in DX into AL.
		asm volatile("inb %1, %0" : "=a"(unused) : "d"(port));
		return;
	}
	if (size == 2) {
		uint16 unused;
		// Reads 2 bytes from the port in DX into AX.
		asm volatile("inw %1, %0" : "=a"(unused) : "d"(port));
		return;
	}
	if (size == 4) {
		uint32 unused;
		// Reads 4 bytes from the port in DX into EAX.
		asm volatile("inl %1, %0" : "=a"(unused) : "d"(port));
	}
	return;
}

// Write data to an I/O port, should result in KVM_EXIT_IO.
GUEST_CODE static noinline void guest_handle_out_dx(struct api_call_3* cmd)
{
	uint16 port = cmd->args[0];
	volatile int size = cmd->args[1];
	uint32 data = (uint32)cmd->args[2];

	if (size == 1) {
		// Writes 1 byte from AL to the port in DX.
		asm volatile("outb %b0, %w1" ::"a"(data), "d"(port));
		return;
	}
	if (size == 2) {
		// Writes 2 bytes from AX to the port in DX.
		asm volatile("outw %w0, %w1" ::"a"(data), "d"(port));
		return;
	}
	if (size == 4) {
		// Writes 4 bytes from EAX to the port in DX.
		asm volatile("outl %k0, %w1" ::"a"(data), "d"(port));
		return;
	}
}

GUEST_CODE static noinline void guest_handle_memwrite(struct api_call_memwrite* cmd)
{
	uint64 dest = cmd->base_addr + cmd->offset;
	uint64 val = cmd->value;
	volatile uint64 len = cmd->len;
	if (len == 1) {
		// Writes 1 byte to dest.
		asm volatile("movb %b0, (%1)" ::"q"(val), "r"(dest) : "memory");
		return;
	}
	if (len == 2) {
		// Writes 2 bytes to dest.
		asm volatile("movw %w0, (%1)" ::"r"(val), "r"(dest) : "memory");
		return;
	}
	if (len == 4) {
		// Writes 4 bytes to dest.
		asm volatile("movl %k0, (%1)" ::"r"(val), "r"(dest) : "memory");
		return;
	}
	if (len == 8) {
		// Writes 8 bytes to dest.
		asm volatile("movq %0, (%1)" ::"r"(val), "r"(dest) : "memory");
		return;
	}
	if (len == 16) {
		// Writes 16 bytes (XMM store) to dest.
		asm volatile(
		    "movq %0, %%xmm0\n\t"
		    "punpcklqdq %%xmm0, %%xmm0\n\t"
		    "movups %%xmm0, (%1)" ::"r"(val),
		    "r"(dest)
		    : "xmm0", "memory");
		return;
	}
}

// See https://wiki.osdev.org/Interrupt_Descriptor_Table#Gate_Descriptor_2.
struct idt_entry_64 {
	uint16 offset_low;
	uint16 selector;
	// Interrupt Stack Table offset in bits 0..2
	uint8 ist;
	// Gate Type, P and DPL.
	uint8 type_attr;
	uint16 offset_mid;
	uint32 offset_high;
	uint32 reserved;
} __attribute__((packed));

// IDT gate setup should be similar to syzos_setup_idt() in the host code.
GUEST_CODE static void set_idt_gate(uint8 vector, uint64 handler)
{
	volatile struct idt_entry_64* idt =
	    (volatile struct idt_entry_64*)(X86_SYZOS_ADDR_VAR_IDT);
	volatile struct idt_entry_64* idt_entry = &idt[vector];
	idt_entry->offset_low = (uint16)handler;
	idt_entry->offset_mid = (uint16)(handler >> 16);
	idt_entry->offset_high = (uint32)(handler >> 32);
	idt_entry->selector = X86_SYZOS_SEL_CODE;
	idt_entry->type_attr = 0x8E;
	idt_entry->ist = 0;
	idt_entry->reserved = 0;
}

GUEST_CODE static noinline void guest_handle_set_irq_handler(struct api_call_2* cmd)
{
	uint8 vector = (uint8)cmd->args[0];
	uint64 type = cmd->args[1];
	volatile uint64 handler_addr = syzos_default_idt_handler(vector);
	if (type == 1)
		handler_addr = executor_fn_guest_addr(dummy_null_handler);
	else if (type == 2)
		handler_addr = executor_fn_guest_addr(uexit_irq_handler);
	set_idt_gate(vector, handler_addr);
}

GUEST_CODE static cpu_vendor_id get_cpu_vendor(void)
{
	volatile struct syzos_globals* globals = (volatile struct syzos_globals*)X86_SYZOS_ADDR_GLOBALS;
	uint64 cached = __atomic_load_n(&globals->vendor, __ATOMIC_RELAXED);
	if (cached == CPU_VENDOR_INTEL || cached == CPU_VENDOR_AMD)
		return (cpu_vendor_id)cached;

	uint32 ebx, eax = 0;

	asm volatile(
	    "cpuid"
	    : "+a"(eax), "=b"(ebx)
	    : // No explicit inputs, EAX is handled by +a.
	    : "ecx", "edx");

	if (ebx == 0x756e6547) { // "Genu[ineIntel]".
		__atomic_store_n(&globals->vendor, CPU_VENDOR_INTEL, __ATOMIC_RELAXED);
		return CPU_VENDOR_INTEL;
	} else if (ebx == 0x68747541) { // "Auth[enticAMD]".
		__atomic_store_n(&globals->vendor, CPU_VENDOR_AMD, __ATOMIC_RELAXED);
		return CPU_VENDOR_AMD;
	} else {
		// Should not happen on AMD64, but for completeness.
		guest_uexit(UEXIT_ASSERT);
		return CPU_VENDOR_INTEL; // Default to Intel if unknown.
	}
}

GUEST_CODE static inline uint64 read_cr0(void)
{
	uint64 val;
	asm volatile("mov %%cr0, %0" : "=r"(val));
	return val;
}

GUEST_CODE static inline uint64 read_cr3(void)
{
	uint64 val;
	asm volatile("mov %%cr3, %0" : "=r"(val));
	return val;
}

GUEST_CODE static inline uint64 read_cr4(void)
{
	uint64 val;
	asm volatile("mov %%cr4, %0" : "=r"(val));
	return val;
}

GUEST_CODE static inline void write_cr4(uint64 val)
{
	asm volatile("mov %0, %%cr4" : : "r"(val));
}

// Write a VMCS field, return false if VMWRITE fails (e.g. the field does not exist or is read-only).
GUEST_CODE static noinline bool vmwrite_noassert(uint64 field, uint64 value)
{
	uint8 error = 0; // nolint
	// 'setna' sets the byte to 1 if CF=1 or ZF=1 (VMfail)
	asm volatile("vmwrite %%rax, %%rbx; setna %0"
		     : "=q"(error)
		     : "a"(value), "b"(field)
		     : "cc", "memory");
	return !error;
}

// Write a VMCS field that is known to exist and to be writable, report UEXIT_ASSERT otherwise.
GUEST_CODE static noinline void vmwrite(uint64 field, uint64 value)
{
	if (!vmwrite_noassert(field, value))
		guest_uexit(UEXIT_ASSERT);
}

GUEST_CODE static noinline uint64 vmread(uint64 field)
{
	uint64 value;
	asm volatile("vmread %%rbx, %%rax"
		     : "=a"(value)
		     : "b"(field)
		     : "cc");
	return value;
}

// Check whether a field exists in the current VMCS: VMREAD fails for unsupported
// fields. Some fields only exist if the CPU supports the corresponding feature,
// and writing them otherwise fails as well. Probing is more reliable than checking
// the VMX capability MSRs, because nested KVM advertises some controls (e.g.
// loading IA32_PERF_GLOBAL_CTRL) without supporting the matching fields.
GUEST_CODE static noinline bool vmcs_field_exists(uint64 field)
{
	uint8 error = 0; // nolint
	// 'setna' sets the byte to 1 if CF=1 or ZF=1 (VMfail)
	asm volatile("vmread %%rbx, %%rax; setna %0"
		     : "=q"(error)
		     : "b"(field)
		     : "rax", "cc");
	return !error;
}

// Check the index of an L2 VM passed by the fuzzer. Out-of-range indices must be rejected, because
// the per-VM memory regions and l2_ctx[] are sized for KVM_MAX_L2_VMS VMs per vCPU, so the handlers
// would otherwise corrupt the state of other VMs and vCPUs.
GUEST_CODE static inline bool nested_vm_id_valid(uint64 vm_id)
{
	return vm_id < KVM_MAX_L2_VMS;
}

// Make the VMCS of the given VM current. Returns false (after reporting the error to the host) on
// failure, e.g. if the VM has not been created. The caller must not touch the VMCS in that case.
GUEST_CODE static noinline bool nested_vmptrld(uint64 cpu_id, uint64 vm_id)
{
	uint64 vmcs_addr = X86_SYZOS_ADDR_VMCS_VMCB(cpu_id, vm_id);
	uint8 error = 0; // nolint
	asm volatile("vmptrld %1; setna %0"
		     : "=q"(error)
		     : "m"(vmcs_addr)
		     : "memory", "cc");
	if (error) {
		guest_uexit(0xE2BAD2);
		return false;
	}
	return true;
}

#define EVMCS_DESC(fld, mask) \
	(((uint32)(mask) << 16) | (uint32) __builtin_offsetof(struct hv_enlightened_vmcs, fld))
#define EVMCS_RANGE(lo, hi, first, mask) \
	if ((f >= (lo)) && (f <= (hi)))  \
	return EVMCS_DESC(first, mask) + (((f - (lo)) >> 1) * (uint32)sizeof(((struct hv_enlightened_vmcs*)0)->first))
#define EVMCS_ONE(enc, fld, mask) \
	if (f == (enc))           \
	return EVMCS_DESC(fld, mask)

// Map a VMCS field encoding to ((hv_clean_fields_mask << 16) | offset) in hv_enlightened_vmcs,
// matching KVM's vmcs_field_to_evmcs_1[], or 0 if unsupported.
GUEST_CODE static noinline uint32 evmcs_field_desc(uint64 field)
{
	if (field & ~0x7FFEULL)
		return 0;
	// Prevent the compiler from generating a switch table.
	volatile uint32 f = (uint32)field;
	// 16-bit fields
	EVMCS_RANGE(VMCS_HOST_ES_SELECTOR, VMCS_HOST_TR_SELECTOR, host_es_selector, HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_GRP1);
	EVMCS_RANGE(VMCS_GUEST_ES_SELECTOR, VMCS_GUEST_TR_SELECTOR, guest_es_selector, HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2);
	EVMCS_ONE(VMCS_VIRTUAL_PROCESSOR_ID, virtual_processor_id, HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_XLAT);
	// 32-bit fields
	EVMCS_RANGE(VMCS_GUEST_ES_LIMIT, VMCS_GUEST_IDTR_LIMIT, guest_es_limit, HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2);
	EVMCS_RANGE(VMCS_GUEST_ES_ACCESS_RIGHTS, VMCS_GUEST_TR_ACCESS_RIGHTS, guest_es_ar_bytes, HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2);
	EVMCS_RANGE(VMCS_VM_INSTRUCTION_ERROR, VMCS_VMX_INSTRUCTION_INFO, vm_instruction_error, HV_VMX_ENLIGHTENED_CLEAN_FIELD_NONE);
	EVMCS_RANGE(VMCS_PAGE_FAULT_ERROR_CODE_MASK, VMCS_CR3_TARGET_COUNT, page_fault_error_code_mask, HV_VMX_ENLIGHTENED_CLEAN_FIELD_ALL);
	EVMCS_RANGE(VMCS_VM_EXIT_MSR_STORE_COUNT, VMCS_VM_EXIT_MSR_LOAD_COUNT, vm_exit_msr_store_count, HV_VMX_ENLIGHTENED_CLEAN_FIELD_ALL);
	EVMCS_RANGE(VMCS_VM_ENTRY_INTR_INFO_FIELD, VMCS_VM_ENTRY_INSTRUCTION_LEN, vm_entry_intr_info_field, HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_EVENT);
	EVMCS_ONE(VMCS_VM_ENTRY_MSR_LOAD_COUNT, vm_entry_msr_load_count, HV_VMX_ENLIGHTENED_CLEAN_FIELD_ALL);
	EVMCS_ONE(VMCS_PIN_BASED_VM_EXEC_CONTROL, pin_based_vm_exec_control, HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_GRP1);
	EVMCS_ONE(VMCS_CPU_BASED_VM_EXEC_CONTROL, cpu_based_vm_exec_control, HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_PROC);
	EVMCS_ONE(VMCS_EXCEPTION_BITMAP, exception_bitmap, HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_EXCPN);
	EVMCS_ONE(VMCS_VM_EXIT_CONTROLS, vm_exit_controls, HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_GRP1);
	EVMCS_ONE(VMCS_VM_ENTRY_CONTROLS, vm_entry_controls, HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_ENTRY);
	EVMCS_ONE(VMCS_TPR_THRESHOLD, tpr_threshold, HV_VMX_ENLIGHTENED_CLEAN_FIELD_NONE);
	EVMCS_ONE(VMCS_SECONDARY_VM_EXEC_CONTROL, secondary_vm_exec_control, HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_GRP1);
	EVMCS_ONE(VMCS_GUEST_INTERRUPTIBILITY_INFO, guest_interruptibility_info, HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_BASIC);
	EVMCS_ONE(VMCS_GUEST_ACTIVITY_STATE, guest_activity_state, HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP1);
	EVMCS_ONE(VMCS_GUEST_SYSENTER_CS, guest_sysenter_cs, HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP1);
	EVMCS_ONE(VMCS_HOST_IA32_SYSENTER_CS, host_ia32_sysenter_cs, HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_GRP1);
	// 64-bit and natural-width fields
	EVMCS_RANGE(VMCS_GUEST_ES_BASE, VMCS_GUEST_IDTR_BASE, guest_es_base, HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP2);
	EVMCS_RANGE(VMCS_CR0_GUEST_HOST_MASK, VMCS_CR4_READ_SHADOW, cr0_guest_host_mask, HV_VMX_ENLIGHTENED_CLEAN_FIELD_CRDR);
	EVMCS_RANGE(VMCS_GUEST_CR0, VMCS_GUEST_CR4, guest_cr0, HV_VMX_ENLIGHTENED_CLEAN_FIELD_CRDR);
	EVMCS_RANGE(VMCS_HOST_CR0, VMCS_HOST_CR4, host_cr0, HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_GRP1);
	EVMCS_RANGE(VMCS_HOST_FS_BASE, VMCS_HOST_IDTR_BASE, host_fs_base, HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_POINTER);
	EVMCS_RANGE(VMCS_GUEST_IA32_DEBUGCTL, VMCS_GUEST_IA32_EFER, guest_ia32_debugctl, HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP1);
	EVMCS_RANGE(VMCS_GUEST_PDPTR0, VMCS_GUEST_PDPTR3, guest_pdptr0, HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP1);
	EVMCS_RANGE(VMCS_HOST_IA32_PAT, VMCS_HOST_IA32_EFER, host_ia32_pat, HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_GRP1);
	EVMCS_RANGE(VMCS_IO_BITMAP_A, VMCS_IO_BITMAP_B, io_bitmap_a, HV_VMX_ENLIGHTENED_CLEAN_FIELD_IO_BITMAP);
	EVMCS_RANGE(VMCS_VM_EXIT_MSR_STORE_ADDR, VMCS_VM_ENTRY_MSR_LOAD_ADDR, vm_exit_msr_store_addr, HV_VMX_ENLIGHTENED_CLEAN_FIELD_ALL);
	EVMCS_RANGE(VMCS_GUEST_SYSENTER_ESP, VMCS_GUEST_SYSENTER_EIP, guest_sysenter_esp, HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP1);
	EVMCS_RANGE(VMCS_HOST_IA32_SYSENTER_ESP, VMCS_HOST_IA32_SYSENTER_EIP, host_ia32_sysenter_esp, HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_GRP1);
	EVMCS_ONE(VMCS_MSR_BITMAP, msr_bitmap, HV_VMX_ENLIGHTENED_CLEAN_FIELD_MSR_BITMAP);
	EVMCS_ONE(VMCS_TSC_OFFSET, tsc_offset, HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_GRP2);
	EVMCS_ONE(VMCS_VIRTUAL_APIC_PAGE_ADDR, virtual_apic_page_addr, HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_GRP2);
	EVMCS_ONE(VMCS_EPT_POINTER, ept_pointer, HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_XLAT);
	EVMCS_ONE(VMCS_XSS_EXIT_BITMAP, xss_exit_bitmap, HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_GRP2);
	EVMCS_ONE(VMCS_ENCLS_EXITING_BITMAP, encls_exiting_bitmap, HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_GRP2);
	EVMCS_ONE(VMCS_TSC_MULTIPLIER, tsc_multiplier, HV_VMX_ENLIGHTENED_CLEAN_FIELD_CONTROL_GRP2);
	EVMCS_ONE(VMCS_GUEST_PHYSICAL_ADDRESS, guest_physical_address, HV_VMX_ENLIGHTENED_CLEAN_FIELD_NONE);
	EVMCS_ONE(VMCS_LINK_POINTER, vmcs_link_pointer, HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP1);
	EVMCS_ONE(VMCS_GUEST_IA32_PERF_GLOBAL_CTRL, guest_ia32_perf_global_ctrl, HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP1);
	EVMCS_ONE(VMCS_GUEST_BNDCFGS, guest_bndcfgs, HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP1);
	EVMCS_ONE(VMCS_HOST_IA32_PERF_GLOBAL_CTRL, host_ia32_perf_global_ctrl, HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_GRP1);
	EVMCS_ONE(VMCS_EXIT_QUALIFICATION, exit_qualification, HV_VMX_ENLIGHTENED_CLEAN_FIELD_NONE);
	EVMCS_ONE(VMCS_GUEST_LINEAR_ADDRESS, guest_linear_address, HV_VMX_ENLIGHTENED_CLEAN_FIELD_NONE);
	EVMCS_ONE(VMCS_GUEST_DR7, guest_dr7, HV_VMX_ENLIGHTENED_CLEAN_FIELD_CRDR);
	EVMCS_ONE(VMCS_GUEST_RSP, guest_rsp, HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_BASIC);
	EVMCS_ONE(VMCS_GUEST_RIP, guest_rip, HV_VMX_ENLIGHTENED_CLEAN_FIELD_NONE);
	EVMCS_ONE(VMCS_GUEST_RFLAGS, guest_rflags, HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_BASIC);
	EVMCS_ONE(VMCS_GUEST_PENDING_DBG_EXCEPTIONS, guest_pending_dbg_exceptions, HV_VMX_ENLIGHTENED_CLEAN_FIELD_GUEST_GRP1);
	EVMCS_ONE(VMCS_HOST_RSP, host_rsp, HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_POINTER);
	EVMCS_ONE(VMCS_HOST_RIP, host_rip, HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_GRP1);
	return 0;
}

#undef EVMCS_DESC
#undef EVMCS_RANGE
#undef EVMCS_ONE

GUEST_CODE static noinline void evmcs_write(uint64 evmcs_gpa, uint64 field, uint32 desc, uint64 value)
{
	uint64 addr = evmcs_gpa + (desc & 0xFFFF);
	uint64 width = (field >> 13) & 3;
	if (width == 0)
		*(volatile uint16*)addr = (uint16)value;
	else if (width == 2)
		*(volatile uint32*)addr = (uint32)value;
	else
		*(volatile uint64*)addr = value;
	((volatile struct hv_enlightened_vmcs*)evmcs_gpa)->hv_clean_fields &= ~(desc >> 16);
}

GUEST_CODE static noinline void nested_deactivate_evmcs_intel(uint64 cpu_id)
{
	volatile struct syzos_globals* globals = (volatile struct syzos_globals*)X86_SYZOS_ADDR_GLOBALS;
	uint8 active = globals->active_evmcs_vm[cpu_id];
	if (!active)
		return;
	uint64 evmcs_gpa = X86_SYZOS_ADDR_EVMCS(cpu_id, active - 1);
	volatile struct hv_vp_assist_page* vp_assist =
	    (volatile struct hv_vp_assist_page*)X86_SYZOS_ADDR_HV_VP_ASSIST(cpu_id);
	// Restore VP assist fields before vmclear so KVM's nested_evmcs_handle_vmclear() runs.
	// Preserve host_es_selector/host_cs_selector (at offset 8) in case the eVMCS cap is disabled
	// in L0, where vmclear treats the page as VMCS12 and zeroes launch_state at offset 8.
	vp_assist->current_nested_vmcs = evmcs_gpa;
	vp_assist->enlighten_vmentry = 1;
	uint64 host_sel_off = __builtin_offsetof(struct hv_enlightened_vmcs, host_es_selector);
	uint32 saved_host_sel = *(volatile uint32*)(evmcs_gpa + host_sel_off);
	asm volatile("vmclear %0" : : "m"(evmcs_gpa) : "memory", "cc");
	*(volatile uint32*)(evmcs_gpa + host_sel_off) = saved_host_sel;
	vp_assist->enlighten_vmentry = 0;
	vp_assist->current_nested_vmcs = ~0ULL;
	globals->active_evmcs_vm[cpu_id] = 0;
}

// Select either eVMCS or regular VMCS for the given L2 VM before accessing its state or entering L2.
GUEST_CODE static noinline bool nested_select_vm_intel(uint64 cpu_id, uint64 vm_id)
{
	volatile struct syzos_globals* globals = (volatile struct syzos_globals*)X86_SYZOS_ADDR_GLOBALS;
	if (globals->evmcs_enabled[cpu_id][vm_id]) {
		if (globals->active_evmcs_vm[cpu_id] != vm_id + 1) {
			nested_deactivate_evmcs_intel(cpu_id);
			volatile struct hv_vp_assist_page* vp_assist =
			    (volatile struct hv_vp_assist_page*)X86_SYZOS_ADDR_HV_VP_ASSIST(cpu_id);
			vp_assist->current_nested_vmcs = X86_SYZOS_ADDR_EVMCS(cpu_id, vm_id);
			vp_assist->enlighten_vmentry = 1;
			globals->active_evmcs_vm[cpu_id] = vm_id + 1;
		}
		return true;
	}
	nested_deactivate_evmcs_intel(cpu_id);
	return nested_vmptrld(cpu_id, vm_id);
}

GUEST_CODE static noinline bool nested_vmcs_field_exists(uint64 cpu_id, uint64 vm_id, uint64 field)
{
	volatile struct syzos_globals* globals = (volatile struct syzos_globals*)X86_SYZOS_ADDR_GLOBALS;
	if (globals->evmcs_enabled[cpu_id][vm_id])
		return evmcs_field_desc(field) != 0;
	return vmcs_field_exists(field);
}

GUEST_CODE static noinline uint64 nested_vmread(uint64 cpu_id, uint64 vm_id, uint64 field)
{
	volatile struct syzos_globals* globals = (volatile struct syzos_globals*)X86_SYZOS_ADDR_GLOBALS;
	if (globals->evmcs_enabled[cpu_id][vm_id]) {
		uint32 desc = evmcs_field_desc(field);
		if (!desc)
			return 0;
		uint64 addr = X86_SYZOS_ADDR_EVMCS(cpu_id, vm_id) + (desc & 0xFFFF);
		uint64 width = (field >> 13) & 3;
		if (width == 0)
			return *(volatile uint16*)addr;
		if (width == 2)
			return *(volatile uint32*)addr;
		return *(volatile uint64*)addr;
	}
	return vmread(field);
}

GUEST_CODE static noinline bool nested_vmwrite_noassert(uint64 cpu_id, uint64 vm_id,
							uint64 field, uint64 value)
{
	volatile struct syzos_globals* globals = (volatile struct syzos_globals*)X86_SYZOS_ADDR_GLOBALS;
	if (globals->evmcs_enabled[cpu_id][vm_id]) {
		uint32 desc = evmcs_field_desc(field);
		if (!desc)
			return false;
		evmcs_write(X86_SYZOS_ADDR_EVMCS(cpu_id, vm_id), field, desc, value);
		return true;
	}
	return vmwrite_noassert(field, value);
}

GUEST_CODE static noinline void nested_vmwrite(uint64 cpu_id, uint64 vm_id, uint64 field, uint64 value)
{
	if (!nested_vmwrite_noassert(cpu_id, vm_id, field, value))
		guest_uexit(UEXIT_ASSERT);
}

GUEST_CODE static noinline bool nested_vmwrite_if_exists(uint64 cpu_id, uint64 vm_id,
							 uint64 field, uint64 value)
{
	if (!nested_vmcs_field_exists(cpu_id, vm_id, field))
		return false;
	nested_vmwrite(cpu_id, vm_id, field, value);
	return true;
}

GUEST_CODE static noinline void nested_vmcs_set_bits(uint64 cpu_id, uint64 vm_id,
						     uint64 field, uint64 bits)
{
	nested_vmwrite(cpu_id, vm_id, field, nested_vmread(cpu_id, vm_id, field) | bits);
}

GUEST_CODE static noinline void vmcb_write16(uint64 vmcb, uint16 offset, uint16 val)
{
	*((volatile uint16*)(vmcb + offset)) = val;
}

GUEST_CODE static noinline void vmcb_write32(uint64 vmcb, uint16 offset, uint32 val)
{
	*((volatile uint32*)(vmcb + offset)) = val;
}

GUEST_CODE static noinline uint32 vmcb_read32(uint64 vmcb, uint16 offset)
{
	return *((volatile uint32*)(vmcb + offset));
}

GUEST_CODE static noinline void vmcb_write64(uint64 vmcb, uint16 offset, uint64 val)
{
	*((volatile uint64*)(vmcb + offset)) = val;
}

GUEST_CODE static noinline uint64 vmcb_read64(volatile uint8* vmcb, uint16 offset)
{
	return *((volatile uint64*)(vmcb + offset));
}

GUEST_CODE static void guest_memset(void* s, uint8 c, int size)
{
	volatile uint8* p = (volatile uint8*)s;
	for (int i = 0; i < size; i++)
		p[i] = c;
}

GUEST_CODE static void guest_memcpy(void* dst, void* src, int size)
{
	volatile uint8* d = (volatile uint8*)dst;
	volatile uint8* s = (volatile uint8*)src;
	for (int i = 0; i < size; i++)
		d[i] = s[i];
}

// Return EAX of the given CPUID leaf (subleaf 0).
GUEST_CODE static noinline uint32 cpuid_eax(uint32 leaf)
{
	uint32 eax = leaf, ecx = 0;
	asm volatile("cpuid" : "+a"(eax), "+c"(ecx) : : "ebx", "edx");
	return eax;
}

// Return ECX of the given CPUID leaf (subleaf 0).
GUEST_CODE static noinline uint32 cpuid_ecx(uint32 leaf)
{
	uint32 eax = leaf, ecx = 0;
	asm volatile("cpuid" : "+a"(eax), "+c"(ecx) : : "ebx", "edx");
	return ecx;
}

GUEST_CODE static noinline void
nested_enable_vmx_intel(uint64 cpu_id)
{
	// Without VMX (CPUID.1:ECX[5]) setting CR4.VMXE causes a #GP.
	if (!(cpuid_ecx(1) & (1 << 5)))
		return;

	uint64 vmxon_addr = X86_SYZOS_ADDR_VM_ARCH_SPECIFIC(cpu_id);
	uint64 cr4 = read_cr4();
	cr4 |= X86_CR4_VMXE;
	write_cr4(cr4);

	uint64 feature_control = rdmsr(X86_MSR_IA32_FEATURE_CONTROL);
	// Check if Lock bit (bit 0) is clear.
	if ((feature_control & 1) == 0) {
		// If unlocked, set Lock bit (bit 0) and Enable VMX outside SMX bit (bit 2).
		feature_control |= 0b101;
		asm volatile("wrmsr" : : "d"(0x0), "c"(X86_MSR_IA32_FEATURE_CONTROL), "A"(feature_control));
	}

	// Store revision ID at the beginning of VMXON.
	*(uint32*)vmxon_addr = rdmsr(X86_MSR_IA32_VMX_BASIC);
	uint8 error;
	// Can't use enter_vmx_operation() yet, because VMCS is not valid.
	asm volatile("vmxon %1; setna %0"
		     : "=q"(error)
		     : "m"(vmxon_addr)
		     : "memory", "cc");
	if (error) {
		guest_uexit(0xE2BAD0);
		return;
	}
}

GUEST_CODE static noinline void
nested_enable_svm_amd(uint64 cpu_id)
{
	// Without SVM (CPUID.80000001h:ECX[2]) setting EFER.SVME causes a #GP.
	if (!(cpuid_ecx(0x80000001) & (1 << 2)))
		return;

	// Get the Host Save Area (HSAVE) physical address for this CPU.
	// The HSAVE area stores the host processor's state on VMRUN and is restored on VMEXIT.
	uint64 hsave_addr = X86_SYZOS_ADDR_VM_ARCH_SPECIFIC(cpu_id);

	// Set the SVM Enable (SVME) bit in EFER. This enables SVM operations.
	uint64 efer = rdmsr(X86_MSR_IA32_EFER);
	efer |= X86_EFER_SVME;
	wrmsr(X86_MSR_IA32_EFER, efer);

	// Write the physical address of the HSAVE area to the VM_HSAVE_PA MSR.
	// This MSR tells the CPU where to save/restore host state during VMRUN/VMEXIT.
	wrmsr(X86_MSR_VM_HSAVE_PA, hsave_addr);
}

GUEST_CODE static noinline void
guest_handle_enable_nested(struct api_call_1* cmd, uint64 cpu_id)
{
	if (get_cpu_vendor() == CPU_VENDOR_INTEL) {
		nested_enable_vmx_intel(cpu_id);
	} else {
		nested_enable_svm_amd(cpu_id);
	}
}

// Calculate the size of the unused memory region from the boot arguments.
GUEST_CODE static uint64 get_unused_memory_size()
{
	volatile struct syzos_boot_args* args = (volatile struct syzos_boot_args*)X86_SYZOS_ADDR_BOOT_ARGS;
	for (uint32 i = 0; i < args->region_count; i++) {
		if (args->regions[i].gpa == X86_SYZOS_ADDR_UNUSED)
			return args->regions[i].pages * KVM_PAGE_SIZE;
	}
	return 0;
}

// Allocate a page from the X86_SYZOS_ADDR_UNUSED region using a non-reclaiming bump allocator.
GUEST_CODE static uint64 guest_alloc_page()
{
	volatile struct syzos_globals* globals = (volatile struct syzos_globals*)X86_SYZOS_ADDR_GLOBALS;

	// Lazy initialization of total_size using CAS to prevent races.
	if (globals->total_size == 0) {
		uint64 size = get_unused_memory_size();
		// Attempt to swap 0 with the calculated size.
		// If another CPU beat us to it, this does nothing (which is fine).
		__sync_val_compare_and_swap(&globals->total_size, 0, size);
	}

	// Atomic fetch-and-add to reserve space.
	uint64 offset = __sync_fetch_and_add(&globals->alloc_offset, KVM_PAGE_SIZE);

	if (offset >= globals->total_size)
		guest_fatal(UEXIT_ASSERT);

	uint64 ptr = X86_SYZOS_ADDR_UNUSED + offset;
	guest_memset((void*)ptr, 0, KVM_PAGE_SIZE);
	return ptr;
}

// Helper to map a page in L2's EPT/NPT.
GUEST_CODE static void l2_map_page(uint64 cpu_id, uint64 vm_id, uint64 gpa, uint64 host_pa, uint64 flags)
{
	// Page table root (PML4).
	uint64 pml4_addr = X86_SYZOS_ADDR_VM_PGTABLE(cpu_id, vm_id);
	volatile uint64* pml4 = (volatile uint64*)pml4_addr;

	// Allocate Level 4 entries.
	uint64 pml4_idx = (gpa >> 39) & 0x1FF;
	if (!(pml4[pml4_idx] & X86_PDE64_PRESENT)) {
		uint64 page = guest_alloc_page();
		pml4[pml4_idx] = page | X86_PDE64_PRESENT | X86_PDE64_RW | X86_PDE64_USER;
	}

	// Allocate Level 3 entries.
	volatile uint64* pdpt = (volatile uint64*)(pml4[pml4_idx] & ~0xFFF);
	uint64 pdpt_idx = (gpa >> 30) & 0x1FF;
	if (!(pdpt[pdpt_idx] & X86_PDE64_PRESENT)) {
		uint64 page = guest_alloc_page();
		pdpt[pdpt_idx] = page | X86_PDE64_PRESENT | X86_PDE64_RW | X86_PDE64_USER;
	}

	// Allocate Level 2 entries.
	volatile uint64* pd = (volatile uint64*)(pdpt[pdpt_idx] & ~0xFFF);
	uint64 pd_idx = (gpa >> 21) & 0x1FF;
	if (!(pd[pd_idx] & X86_PDE64_PRESENT)) {
		uint64 page = guest_alloc_page();
		pd[pd_idx] = page | X86_PDE64_PRESENT | X86_PDE64_RW | X86_PDE64_USER;
	}

	// Update Level 1 (PT).
	volatile uint64* pt = (volatile uint64*)(pd[pd_idx] & ~0xFFF);
	uint64 pt_idx = (gpa >> 12) & 0x1FF;

	// Map if not present.
	if (!(pt[pt_idx] & X86_PDE64_PRESENT))
		pt[pt_idx] = (host_pa & ~0xFFF) | flags;
}

// Allocate the globals page of an L2 VM, see setup_l2_page_tables().
GUEST_CODE static uint64 l2_alloc_globals_page()
{
	uint64 page = guest_alloc_page();
	volatile struct syzos_globals* l2_globals = (volatile struct syzos_globals*)page;
	// L2 sees the same heap pages as L1, which already uses them (e.g. for the page tables of
	// this very VM), so L2 must not allocate from the heap. Mark its heap as exhausted.
	l2_globals->total_size = KVM_PAGE_SIZE;
	l2_globals->alloc_offset = KVM_PAGE_SIZE;
	return page;
}

GUEST_CODE static noinline void setup_l2_page_tables(cpu_vendor_id vendor, uint64 cpu_id, uint64 vm_id, uint64 unused_pages)
{
	// Note: PML4 and MSR Bitmap must be zeroed by the caller (nested_create_vm)
	// so that this function can be called additively by nested_load_syzos.
	// Intel EPT: set Read, Write, Execute.
	// AMD NPT: set Present, Write, User.
	// The accessed and dirty bits are deliberately left clear, so that L0 has to set them when
	// L2 touches the page: always for NPT, and for EPT if the fuzzer enables the A/D bits in the
	// EPT pointer (which is also what makes L0 log the dirty pages to the PML buffer of L1).
	uint64 flags = X86_PDE64_PRESENT | X86_PDE64_RW | X86_PDE64_USER;
	if (vendor == CPU_VENDOR_INTEL)
		flags |= EPT_MEMTYPE_WB;

	// Replicate L1 memory layout from boot args.
	volatile struct syzos_boot_args* args = (volatile struct syzos_boot_args*)X86_SYZOS_ADDR_BOOT_ARGS;
	for (uint32 i = 0; i < args->region_count; i++) {
		struct mem_region r;
		r.gpa = args->regions[i].gpa;
		r.pages = args->regions[i].pages;
		r.flags = args->regions[i].flags;

		// Skip NO_HOST_MEM regions (like the Exit/UEXIT region).
		// This ensures that L2 accesses to these pages cause a nested page fault
		// (EPT Violation / NPT Fault), allowing L1 to intercept and modify the exit code.
		if (r.flags & MEM_REGION_FLAG_NO_HOST_MEM)
			continue;

		// Skip the huge unused heap for now, map fixed small heap if needed or handled by guest_alloc.
		// If unused_pages > 0, we map that many pages from the unused region.
		if (r.flags & MEM_REGION_FLAG_REMAINING) {
			// Map at least a few pages for the allocator overhead if 0 is passed.
			r.pages = (unused_pages < 16) ? 16 : unused_pages;
		}

		for (int p = 0; p < r.pages; p++) {
			uint64 gpa = r.gpa + (p * KVM_PAGE_SIZE);
			uint64 backing;

			if (r.gpa == X86_SYZOS_ADDR_USER_CODE && (uint64)p == cpu_id) {
				// Map the user code page of this vCPU to the VM's dedicated code buffer.
				// L2 SYZOS runs with the same vCPU index as L1 (see nested_load_syzos),
				// so this is where it looks for its program.
				backing = X86_SYZOS_ADDR_VM_CODE(cpu_id, vm_id);
			} else if (r.gpa == X86_SYZOS_ADDR_GLOBALS) {
				// L2 gets its own globals page: an L2 SYZOS has its own program size,
				// and must not overwrite the globals of L1.
				backing = l2_alloc_globals_page();
			} else if (r.gpa == X86_SYZOS_ADDR_STACK_BOTTOM) {
				// Map the first stack page to the VM's dedicated stack buffer. L2 runs on a single
				// vCPU, so it does not need the other pages, and they must not be identity-mapped
				// to the stacks of L1 vCPUs.
				if (p != 0)
					continue;
				backing = X86_SYZOS_ADDR_VM_STACK(cpu_id, vm_id);
			} else {
				// Identity map all other regions to prevent L1 OOM exhaustion.
				// The L2 guest is transient and does not need duplicates of L1's GDT/IDT/TSS/Heap.
				backing = gpa;
			}
			l2_map_page(cpu_id, vm_id, gpa, backing, flags);
		}
	}
}

GUEST_CODE static noinline void init_vmcs_control_fields(uint64 cpu_id, uint64 vm_id)
{
	// Read and write Pin-Based controls from TRUE MSR.
	uint64 vmx_msr = rdmsr(X86_MSR_IA32_VMX_TRUE_PINBASED_CTLS);
	vmwrite(VMCS_PIN_BASED_VM_EXEC_CONTROL, (uint32)vmx_msr);

	// Setup Secondary Processor-Based controls: enable EPT.
	vmx_msr = (uint32)rdmsr(X86_MSR_IA32_VMX_PROCBASED_CTLS2);
	vmx_msr |= SECONDARY_EXEC_ENABLE_EPT | SECONDARY_EXEC_ENABLE_RDTSCP;
	vmwrite(VMCS_SECONDARY_VM_EXEC_CONTROL, vmx_msr);

	// Read and write Primary Processor-Based controls from TRUE MSR.
	// We also add the bit to enable the secondary controls.
	vmx_msr = rdmsr(X86_MSR_IA32_VMX_TRUE_PROCBASED_CTLS);
	vmx_msr |= CPU_BASED_ACTIVATE_SECONDARY_CONTROLS;
	// Exit on HLT and RDTSC.
	vmx_msr |= CPU_BASED_HLT_EXITING | CPU_BASED_RDTSC_EXITING;
	vmwrite(VMCS_CPU_BASED_VM_EXEC_CONTROL, (uint32)vmx_msr);

	// Set up VM-Exit controls via TRUE MSR: indicate a 64-bit host.
	vmx_msr = rdmsr(X86_MSR_IA32_VMX_TRUE_EXIT_CTLS);
	vmwrite(VMCS_VM_EXIT_CONTROLS, (uint32)vmx_msr | VM_EXIT_HOST_ADDR_SPACE_SIZE);
	// Read and write VM-Entry controls from TRUE MSR
	// We add the bit to indicate a 64-bit guest.
	vmx_msr = rdmsr(X86_MSR_IA32_VMX_TRUE_ENTRY_CTLS);
	vmwrite(VMCS_VM_ENTRY_CONTROLS, (uint32)vmx_msr | VM_ENTRY_IA32E_MODE);

	// Set up the EPT Pointer.
	// We use the L2 PML4 address we calculate in guest_handle_create_nested_vm.
	// The EPT Pointer has:
	// - Memory Type = 6 (Write-Back)
	// - Page-Walk Length = 3 (meaning 4 levels: PML4, PDPT, PD, PT)
	// - Address of the PML4 table
	uint64 eptp = (X86_SYZOS_ADDR_VM_PGTABLE(cpu_id, vm_id) & ~0xFFF) | (6 << 0) | (3 << 3);
	vmwrite(VMCS_EPT_POINTER, eptp);

	// Set CR0/CR4 masks and shadows.
	// This simple setup (masks=0) means any guest CR0/CR4 write is allowed
	// and won't cause a VM-Exit.
	vmwrite(VMCS_CR0_GUEST_HOST_MASK, 0);
	vmwrite(VMCS_CR4_GUEST_HOST_MASK, 0);
	vmwrite(VMCS_CR0_READ_SHADOW, read_cr0());
	vmwrite(VMCS_CR4_READ_SHADOW, read_cr4());

	// Disable the bitmaps which we do not use.
	vmwrite(VMCS_MSR_BITMAP, 0);
	vmwrite(VMCS_VMREAD_BITMAP, 0);
	vmwrite(VMCS_VMWRITE_BITMAP, 0);

	// Intercept #UD (Invalid Opcode)
	vmwrite(VMCS_EXCEPTION_BITMAP, (1 << 6));

	// Initialize the fields we do not use: the SDM requires all fields to be
	// initialized with VMWRITE. Skip the ones that do not exist on this CPU.
	if (vmcs_field_exists(VMCS_VIRTUAL_PROCESSOR_ID))
		vmwrite(VMCS_VIRTUAL_PROCESSOR_ID, 0);
	if (vmcs_field_exists(VMCS_POSTED_INTR_NV))
		vmwrite(VMCS_POSTED_INTR_NV, 0);
	if (vmcs_field_exists(VMCS_VM_FUNCTION_CONTROL))
		vmwrite(VMCS_VM_FUNCTION_CONTROL, 0);
	if (vmcs_field_exists(VMCS_EPTP_LIST_ADDRESS))
		vmwrite(VMCS_EPTP_LIST_ADDRESS, 0);
	vmwrite(VMCS_PAGE_FAULT_ERROR_CODE_MASK, 0);
	vmwrite(VMCS_PAGE_FAULT_ERROR_CODE_MATCH, -1);
	vmwrite(VMCS_CR3_TARGET_COUNT, 0);
	vmwrite(VMCS_VM_EXIT_MSR_STORE_COUNT, 0);
	vmwrite(VMCS_VM_EXIT_MSR_LOAD_COUNT, 0);
	vmwrite(VMCS_VM_ENTRY_MSR_LOAD_COUNT, 0);
	vmwrite(VMCS_VM_ENTRY_INTR_INFO_FIELD, 0);
	if (vmcs_field_exists(VMCS_TPR_THRESHOLD))
		vmwrite(VMCS_TPR_THRESHOLD, 0);
}

// Common L2 exit reasons for Intel and AMD.
typedef enum {
	SYZOS_NESTED_EXIT_REASON_HLT = 1,
	SYZOS_NESTED_EXIT_REASON_INVD = 2,
	SYZOS_NESTED_EXIT_REASON_CPUID = 3,
	SYZOS_NESTED_EXIT_REASON_RDTSC = 4,
	SYZOS_NESTED_EXIT_REASON_RDTSCP = 5,
	SYZOS_NESTED_EXIT_REASON_EPT_VIOLATION = 6,
	SYZOS_NESTED_EXIT_REASON_UNKNOWN = 0xFF,
} syz_nested_exit_reason;

GUEST_CODE static void handle_nested_uexit(uint64 exit_code)
{
	// Increment the nesting level (top byte).
	uint64 level = (exit_code >> 56) + 1;
	exit_code = (exit_code & 0x00FFFFFFFFFFFFFFULL) | (level << 56);

	// Perform L1 uexit with the modified code.
	guest_uexit(exit_code);
	// guest_uexit terminates, so we don't return.
}

GUEST_CODE static void guest_uexit_l2(uint64 exit_reason, syz_nested_exit_reason mapped_reason,
				      cpu_vendor_id vendor)
{
	if (mapped_reason != SYZOS_NESTED_EXIT_REASON_UNKNOWN) {
		guest_uexit(0xe2e20000 | mapped_reason);
	} else if (vendor == CPU_VENDOR_INTEL) {
		guest_uexit(0xe2110000 | exit_reason);
	} else {
		// AMD exit codes are 64-bit, and the error ones (e.g. VMEXIT_INVALID) are negative.
		// Only report the low 16 bits, so that they do not turn into UEXIT_END and friends.
		guest_uexit(0xe2aa0000 | (exit_reason & 0xffff));
	}
}

#define EXIT_REASON_CPUID 0xa
#define EXIT_REASON_HLT 0xc
#define EXIT_REASON_INVD 0xd
#define EXIT_REASON_EPT_VIOLATION 0x30
#define EXIT_REASON_RDTSC 0x10
#define EXIT_REASON_RDTSCP 0x33

GUEST_CODE static syz_nested_exit_reason map_intel_exit_reason(uint64 basic_reason)
{
	// Disable optimizations.
	volatile uint64 reason = basic_reason;
	if (reason == EXIT_REASON_HLT)
		return SYZOS_NESTED_EXIT_REASON_HLT;
	if (reason == EXIT_REASON_INVD)
		return SYZOS_NESTED_EXIT_REASON_INVD;
	if (reason == EXIT_REASON_CPUID)
		return SYZOS_NESTED_EXIT_REASON_CPUID;
	if (reason == EXIT_REASON_RDTSC)
		return SYZOS_NESTED_EXIT_REASON_RDTSC;
	if (reason == EXIT_REASON_RDTSCP)
		return SYZOS_NESTED_EXIT_REASON_RDTSCP;
	if (reason == EXIT_REASON_EPT_VIOLATION)
		return SYZOS_NESTED_EXIT_REASON_EPT_VIOLATION;
	return SYZOS_NESTED_EXIT_REASON_UNKNOWN;
}

// Basic exit reasons 0-63 of the VM exits caused by the execution of an instruction that L1 is
// expected to emulate and skip: CPUID (10), INVD (13), INVLPG (14), RDPMC (15), RDTSC (16),
// VMCALL (18), VMX instructions (19-27), CR access (28), DR access (29), I/O (30), RDMSR (31),
// WRMSR (32), MWAIT (36), MONITOR (39), PAUSE (40), GDTR/IDTR access (46), LDTR/TR access (47),
// INVEPT (50), RDTSCP (51), INVVPID (53), WBINVD (54), XSETBV (55), RDRAND (57), INVPCID (58),
// VMFUNC (59), ENCLS (60), RDSEED (61), XSAVES (63).
// HLT (12) is deliberately missing: an L2 program ends with HLT, and skipping it would make L2
// run into the memory past its code when resumed.
#define EXIT_REASONS_TO_SKIP_INTEL 0xbeecc191fffde400ULL
#define EXIT_REASON_XRSTORS 64

// After reporting an exit caused by an instruction, move the L2 RIP past it, so that resuming L2
// executes the next instruction instead of exiting for the same reason again.
GUEST_CODE static void advance_l2_rip_intel(uint64 exit_reason, uint64 cpu_id, uint64 vm_id)
{
	if (exit_reason >> 16)
		return;
	uint64 basic_reason = exit_reason & 0xFFFF;
	if ((basic_reason != EXIT_REASON_XRSTORS) &&
	    ((basic_reason >= 64) || !((EXIT_REASONS_TO_SKIP_INTEL >> basic_reason) & 1)))
		return;
	// The CPU reports the length of the instruction for all these exits.
	nested_vmwrite(cpu_id, vm_id, VMCS_GUEST_RIP,
		       nested_vmread(cpu_id, vm_id, VMCS_GUEST_RIP) +
			   nested_vmread(cpu_id, vm_id, VMCS_VM_EXIT_INSTRUCTION_LEN));
}

// Called from inline asm; see the forward declaration above for why this is non-static.
__attribute__((used))
GUEST_CODE void
// NOLINTNEXTLINE(misc-definitions-in-headers)
nested_vm_exit_handler_intel(struct l2_guest_regs* regs)
{
	volatile struct syzos_globals* globals = (volatile struct syzos_globals*)X86_SYZOS_ADDR_GLOBALS;
	// Recover cpu_id from the stack. It was pushed before L1 registers.
	// Stack: [cpu_id] [launch] [L1 GPRs x6] [L2 GPRs x15]
	// Index: 22       21       15..20        0..14
	// regs points to the start of L2 GPRs.
	uint64 cpu_id = *(uint64*)((char*)regs + sizeof(struct l2_guest_regs) + 7 * 8);
	uint64 vm_id = globals->active_vm_id[cpu_id];

	// Persist L2 registers.
	guest_memcpy((void*)&globals->l2_ctx[cpu_id][vm_id], regs, sizeof(struct l2_guest_regs));

	uint64 exit_reason = nested_vmread(cpu_id, vm_id, VMCS_VM_EXIT_REASON);
	uint64 basic_reason = exit_reason & 0xFFFF;

	// Handle EPT Violation (Nested UEXIT).
	if ((exit_reason >> 16) == 0 && basic_reason == EXIT_REASON_EPT_VIOLATION) {
		uint64 gpa = nested_vmread(cpu_id, vm_id, VMCS_GUEST_PHYSICAL_ADDRESS);
		// Only handle violations on the specific UEXIT page.
		if ((gpa & ~0xFFF) == X86_SYZOS_ADDR_EXIT) {
			// This is a uexit from L2.
			// We enforced usage of RAX in guest_uexit.
			// Read RAX from the saved L2 guest registers.
			// Note: On Intel exit, guest registers are NOT saved to VMCS.
			// They are saved to 'regs' by our asm wrapper.
			handle_nested_uexit(regs->rax);
			// Advance L2 RIP by 3 bytes (movq %rax, (%rdx) is 3 bytes).
			nested_vmwrite(cpu_id, vm_id, VMCS_GUEST_RIP,
				       nested_vmread(cpu_id, vm_id, VMCS_GUEST_RIP) + 3);
			return;
		}
	}

	syz_nested_exit_reason mapped_reason = (exit_reason >> 16)
						   ? SYZOS_NESTED_EXIT_REASON_UNKNOWN
						   : map_intel_exit_reason(basic_reason);
	guest_uexit_l2(exit_reason, mapped_reason, CPU_VENDOR_INTEL);
	advance_l2_rip_intel(exit_reason, cpu_id, vm_id);
}

extern char after_vmentry_label;
__attribute__((naked)) GUEST_CODE static void nested_vm_exit_handler_intel_asm(void)
{
	asm volatile(R"(
      // Save L2's GPRs. This creates the 'struct l2_guest_regs' on the stack.
      // We push in reverse order so that RAX ends up at offset 0 (Top of Stack).
      push %%r15
      push %%r14
      push %%r13
      push %%r12
      push %%r11
      push %%r10
      push %%r9
      push %%r8
      push %%rbp
      push %%rdi
      push %%rsi
      push %%rdx
      push %%rcx
      push %%rbx
      push %%rax

      // Prepare arguments for the C handler:
      //    arg1 (RDI) = pointer to the saved registers
      mov %%rsp, %%rdi

      // Align RSP to 16 bytes for the C call, since VMCS_HOST_RSP depends on
      // the compiler's stack frame around the vmentry inline asm.
      mov %%rsp, %%rbp
      andq $-16, %%rsp

      // Call the C handler.
      call nested_vm_exit_handler_intel

      // Restore pre-alignment RSP pointing at struct l2_guest_regs.
      mov %%rbp, %%rsp

      // The C handler has processed the exit. Now, return to the L1 command
      // processing loop. VMX remains enabled.

      // 1. Discard L2 GPRs.
      add %[l2_regs_size], %%rsp

      // 2. Restore L1 callee-saved registers.
      // Order must be reverse of push: r15, r14, r13, r12, rbp, rbx.
      pop %%r15
      pop %%r14
      pop %%r13
      pop %%r12
      pop %%rbp
      pop %%rbx

      // 3. Discard launch flag and cpu_id.
      add $16, %%rsp

      // 4. Restore Red Zone.
      add $128, %%rsp

      // Jump to L1 main flow
      jmp after_vmentry_label
	)"

		     : : [l2_regs_size] "i"(sizeof(struct l2_guest_regs)) : "memory", "cc", "rdi");
}

#define VMEXIT_RDTSC 0x6e
#define VMEXIT_CPUID 0x72
#define VMEXIT_INVD 0x76
#define VMEXIT_HLT 0x78
#define VMEXIT_NPF 0x400
#define VMEXIT_RDTSCP 0x87

GUEST_CODE static syz_nested_exit_reason map_amd_exit_reason(uint64 basic_reason)
{
	// Disable optimizations.
	volatile uint64 reason = basic_reason;
	if (reason == VMEXIT_HLT)
		return SYZOS_NESTED_EXIT_REASON_HLT;
	if (reason == VMEXIT_INVD)
		return SYZOS_NESTED_EXIT_REASON_INVD;
	if (reason == VMEXIT_CPUID)
		return SYZOS_NESTED_EXIT_REASON_CPUID;
	if (reason == VMEXIT_RDTSC)
		return SYZOS_NESTED_EXIT_REASON_RDTSC;
	if (reason == VMEXIT_RDTSCP)
		return SYZOS_NESTED_EXIT_REASON_RDTSCP;
	if (reason == VMEXIT_NPF)
		return SYZOS_NESTED_EXIT_REASON_EPT_VIOLATION;
	return SYZOS_NESTED_EXIT_REASON_UNKNOWN;
}

// Exit codes of the #VMEXITs caused by the execution of an instruction that L1 is expected to
// emulate and skip. CR and DR accesses (0x00-0x3f) are checked separately.
// Codes 0x40-0x7f: IDTR/GDTR/LDTR/TR access (0x66-0x6d), RDTSC (0x6e), RDPMC (0x6f), CPUID (0x72),
// INVD (0x76), PAUSE (0x77), INVLPG (0x79), INVLPGA (0x7a), I/O (0x7b), MSR access (0x7c).
// HLT (0x78) is deliberately missing: an L2 program ends with HLT, and skipping it would make L2
// run into the memory past its code when resumed. IRET (0x74) is intercepted before it executes
// and cannot be skipped either.
#define EXIT_CODES_TO_SKIP_AMD_40 0x1ec4ffc000000000ULL
// Codes 0x80-0xbf: VMRUN, VMMCALL, VMLOAD, VMSAVE, STGI, CLGI, SKINIT, RDTSCP (0x80-0x87),
// WBINVD (0x89), MONITOR (0x8a), MWAIT (0x8b), XSETBV (0x8d), RDPRU (0x8e), INVPCID (0xa2).
#define EXIT_CODES_TO_SKIP_AMD_80 0x400006effULL

GUEST_CODE static bool amd_exit_is_skippable(uint64 code)
{
	if (code < 0x40)
		return true;
	if (code < 0x80)
		return (EXIT_CODES_TO_SKIP_AMD_40 >> (code - 0x40)) & 1;
	if (code < 0xc0)
		return (EXIT_CODES_TO_SKIP_AMD_80 >> (code - 0x80)) & 1;
	return false;
}

// After reporting an exit caused by an instruction, move the L2 RIP past it, so that resuming L2
// executes the next instruction instead of exiting for the same reason again.
GUEST_CODE static void advance_l2_rip_amd(uint64 basic_reason, uint64 cpu_id, uint64 vm_id)
{
	// Disable optimizations.
	volatile uint64 reason = basic_reason;
	if (!amd_exit_is_skippable(reason))
		return;
	uint64 vmcb_addr = X86_SYZOS_ADDR_VMCS_VMCB(cpu_id, vm_id);
	uint64 rip = vmcb_read64((volatile uint8*)vmcb_addr, VMCB_GUEST_RIP);
	// With the NRIPS feature the CPU reports the address of the next instruction.
	uint64 next_rip = vmcb_read64((volatile uint8*)vmcb_addr, VMCB_CTRL_NEXT_RIP);
	if (next_rip) {
		rip = next_rip;
	} else if ((reason == VMEXIT_INVD) || (reason == VMEXIT_CPUID) || (reason == VMEXIT_RDTSC)) {
		// Without NRIPS only skip the instructions with a fixed length.
		rip += 2;
	} else if (reason == VMEXIT_RDTSCP) {
		// We insist on a single-line compound statement for else-if.
		rip += 3;
	}
	vmcb_write64(vmcb_addr, VMCB_GUEST_RIP, rip);
}

// Called from inline asm; see the forward declaration above for why this is non-static.
__attribute__((used)) GUEST_CODE void
// NOLINTNEXTLINE(misc-definitions-in-headers)
nested_vm_exit_handler_amd(uint64 exit_reason, struct l2_guest_regs* regs)
{
	volatile struct syzos_globals* globals = (volatile struct syzos_globals*)X86_SYZOS_ADDR_GLOBALS;
	// Recover cpu_id from the stack.
	// Stack: [cpu_id] [vmcb_addr] [6 L1 GPRs] [exit_code] [15 L2 GPRs]
	// Index: 23       22          16..21       15          0..14
	// regs points to Index 0.
	uint64 cpu_id = *(uint64*)((char*)regs + sizeof(struct l2_guest_regs) + 8 * 8);
	uint64 vm_id = globals->active_vm_id[cpu_id];

	// Persist L2 registers.
	guest_memcpy((void*)&globals->l2_ctx[cpu_id][vm_id], regs, sizeof(struct l2_guest_regs));

	volatile uint64 basic_reason = exit_reason & 0xFFFF;

	// Handle NPT Fault (Nested UEXIT).
	if (basic_reason == VMEXIT_NPF) {
		uint64 vmcb_addr = X86_SYZOS_ADDR_VMCS_VMCB(cpu_id, vm_id);
		// EXITINFO2 contains the faulting GPA.
		uint64 fault_gpa = vmcb_read64((volatile uint8*)vmcb_addr, VMCB_EXITINFO2);
		if ((fault_gpa & ~0xFFF) == X86_SYZOS_ADDR_EXIT) {
			// RAX is in the saved L2 regs.
			handle_nested_uexit(regs->rax);
			// Advance L2 RIP by 3 bytes.
			uint64 rip = vmcb_read64((volatile uint8*)vmcb_addr, VMCB_GUEST_RIP);
			vmcb_write64(vmcb_addr, VMCB_GUEST_RIP, rip + 3);
			return;
		}
	}

	syz_nested_exit_reason mapped_reason = map_amd_exit_reason(basic_reason);
	guest_uexit_l2(exit_reason, mapped_reason, CPU_VENDOR_AMD);
	advance_l2_rip_amd(basic_reason, cpu_id, vm_id);
}

GUEST_CODE static noinline void init_vmcs_host_state(void)
{
	// Segment Selectors.
	vmwrite(VMCS_HOST_CS_SELECTOR, X86_SYZOS_SEL_CODE);
	vmwrite(VMCS_HOST_DS_SELECTOR, X86_SYZOS_SEL_DATA);
	vmwrite(VMCS_HOST_ES_SELECTOR, X86_SYZOS_SEL_DATA);
	vmwrite(VMCS_HOST_SS_SELECTOR, X86_SYZOS_SEL_DATA);
	vmwrite(VMCS_HOST_FS_SELECTOR, X86_SYZOS_SEL_DATA);
	vmwrite(VMCS_HOST_GS_SELECTOR, X86_SYZOS_SEL_DATA);
	vmwrite(VMCS_HOST_TR_SELECTOR, X86_SYZOS_SEL_TSS64);

	// Base addresses.
	vmwrite(VMCS_HOST_TR_BASE, X86_SYZOS_ADDR_VAR_TSS);
	vmwrite(VMCS_HOST_GDTR_BASE, X86_SYZOS_ADDR_GDT);
	vmwrite(VMCS_HOST_IDTR_BASE, X86_SYZOS_ADDR_VAR_IDT);
	vmwrite(VMCS_HOST_FS_BASE, rdmsr(X86_MSR_FS_BASE));
	vmwrite(VMCS_HOST_GS_BASE, rdmsr(X86_MSR_GS_BASE));

	// Exit handler in RIP.
	vmwrite(VMCS_HOST_RIP, executor_fn_guest_addr(nested_vm_exit_handler_intel_asm));

	// Control Registers.
	vmwrite(VMCS_HOST_CR0, read_cr0());
	vmwrite(VMCS_HOST_CR3, read_cr3());
	vmwrite(VMCS_HOST_CR4, read_cr4());

	// MSRs.
	vmwrite(VMCS_HOST_IA32_PAT, rdmsr(X86_MSR_IA32_CR_PAT));
	vmwrite(VMCS_HOST_IA32_EFER, rdmsr(X86_MSR_IA32_EFER));
	// The field may not exist without hardware support for loading IA32_PERF_GLOBAL_CTRL,
	// and the MSR itself may not exist without a vPMU.
	if (vmcs_field_exists(VMCS_HOST_IA32_PERF_GLOBAL_CTRL))
		vmwrite(VMCS_HOST_IA32_PERF_GLOBAL_CTRL, read_perf_global_ctrl());
	vmwrite(VMCS_HOST_IA32_SYSENTER_CS, rdmsr(X86_MSR_IA32_SYSENTER_CS));
	vmwrite(VMCS_HOST_IA32_SYSENTER_ESP, rdmsr(X86_MSR_IA32_SYSENTER_ESP));
	vmwrite(VMCS_HOST_IA32_SYSENTER_EIP, rdmsr(X86_MSR_IA32_SYSENTER_EIP));
}

#define COPY_VMCS_FIELD(GUEST_FIELD, HOST_FIELD) \
	vmwrite(GUEST_FIELD, vmread(HOST_FIELD))

#define SETUP_L2_SEGMENT(SEG, SELECTOR, BASE, LIMIT, AR) \
	vmwrite(VMCS_GUEST_##SEG##_SELECTOR, SELECTOR);  \
	vmwrite(VMCS_GUEST_##SEG##_BASE, BASE);          \
	vmwrite(VMCS_GUEST_##SEG##_LIMIT, LIMIT);        \
	vmwrite(VMCS_GUEST_##SEG##_ACCESS_RIGHTS, AR);

GUEST_CODE static noinline void init_vmcs_guest_state(uint64 cpu_id, uint64 vm_id)
{
	uint64 l2_code_addr = X86_SYZOS_ADDR_VM_CODE(cpu_id, vm_id);
	uint64 l2_stack_addr = X86_SYZOS_ADDR_VM_STACK(cpu_id, vm_id);
	// Segment Registers.
	SETUP_L2_SEGMENT(CS, vmread(VMCS_HOST_CS_SELECTOR), 0, 0xFFFFFFFF, VMX_AR_64BIT_CODE);
	SETUP_L2_SEGMENT(DS, vmread(VMCS_HOST_DS_SELECTOR), 0, 0xFFFFFFFF, VMX_AR_64BIT_DATA_STACK);
	SETUP_L2_SEGMENT(ES, vmread(VMCS_HOST_ES_SELECTOR), 0, 0xFFFFFFFF, VMX_AR_64BIT_DATA_STACK);
	SETUP_L2_SEGMENT(SS, vmread(VMCS_HOST_SS_SELECTOR), 0, 0xFFFFFFFF, VMX_AR_64BIT_DATA_STACK);
	SETUP_L2_SEGMENT(FS, vmread(VMCS_HOST_FS_SELECTOR), vmread(VMCS_HOST_FS_BASE), 0xFFFFFFFF, VMX_AR_64BIT_DATA_STACK);
	SETUP_L2_SEGMENT(GS, vmread(VMCS_HOST_GS_SELECTOR), vmread(VMCS_HOST_GS_BASE), 0xFFFFFFFF, VMX_AR_64BIT_DATA_STACK);

	// Task and LDT Registers.
	SETUP_L2_SEGMENT(TR, vmread(VMCS_HOST_TR_SELECTOR), vmread(VMCS_HOST_TR_BASE), 0x67, VMX_AR_TSS_BUSY);
	SETUP_L2_SEGMENT(LDTR, 0, 0, 0, VMX_AR_LDTR_UNUSABLE);

	// Control Registers & CPU State.
	vmwrite(VMCS_GUEST_CR0, vmread(VMCS_HOST_CR0));
	vmwrite(VMCS_GUEST_CR3, vmread(VMCS_HOST_CR3));
	vmwrite(VMCS_GUEST_CR4, vmread(VMCS_HOST_CR4));
	vmwrite(VMCS_GUEST_RIP, l2_code_addr);
	vmwrite(VMCS_GUEST_RSP, l2_stack_addr + KVM_PAGE_SIZE - 8);
	vmwrite(VMCS_GUEST_RFLAGS, RFLAGS_1_BIT);
	// TODO
	vmwrite(VMCS_GUEST_DR7, 0x400);

	// MSRs - Copy from host or set to default.
	COPY_VMCS_FIELD(VMCS_GUEST_IA32_EFER, VMCS_HOST_IA32_EFER);
	COPY_VMCS_FIELD(VMCS_GUEST_IA32_PAT, VMCS_HOST_IA32_PAT);
	if (vmcs_field_exists(VMCS_GUEST_IA32_PERF_GLOBAL_CTRL) &&
	    vmcs_field_exists(VMCS_HOST_IA32_PERF_GLOBAL_CTRL))
		COPY_VMCS_FIELD(VMCS_GUEST_IA32_PERF_GLOBAL_CTRL, VMCS_HOST_IA32_PERF_GLOBAL_CTRL);
	COPY_VMCS_FIELD(VMCS_GUEST_SYSENTER_CS, VMCS_HOST_IA32_SYSENTER_CS);
	COPY_VMCS_FIELD(VMCS_GUEST_SYSENTER_ESP, VMCS_HOST_IA32_SYSENTER_ESP);
	COPY_VMCS_FIELD(VMCS_GUEST_SYSENTER_EIP, VMCS_HOST_IA32_SYSENTER_EIP);
	vmwrite(VMCS_GUEST_IA32_DEBUGCTL, 0);

	// Descriptor Tables.
	vmwrite(VMCS_GUEST_GDTR_BASE, vmread(VMCS_HOST_GDTR_BASE));
	vmwrite(VMCS_GUEST_GDTR_LIMIT, 0xffff);
	vmwrite(VMCS_GUEST_IDTR_BASE, vmread(VMCS_HOST_IDTR_BASE));
	vmwrite(VMCS_GUEST_IDTR_LIMIT, 0xffff);

	// Miscellaneous Fields.
	vmwrite(VMCS_LINK_POINTER, 0xffffffffffffffff);
	// 0 = Active.
	vmwrite(VMCS_GUEST_ACTIVITY_STATE, 0);
	vmwrite(VMCS_GUEST_INTERRUPTIBILITY_INFO, 0);
	vmwrite(VMCS_GUEST_PENDING_DBG_EXCEPTIONS, 0);
	// KVM always emulates the VMX preemption timer and PML, so their fields exist
	// even if the CPU does not support them.
	vmwrite(VMCS_VMX_PREEMPTION_TIMER_VALUE, 0);
	if (vmcs_field_exists(VMCS_GUEST_INTR_STATUS))
		vmwrite(VMCS_GUEST_INTR_STATUS, 0);
	vmwrite(VMCS_GUEST_PML_INDEX, 0);
}

GUEST_CODE static noinline void
nested_create_vm_intel(struct api_call_1* cmd, uint64 cpu_id)
{
	uint64 vm_id = cmd->arg;
	volatile struct syzos_globals* globals = (volatile struct syzos_globals*)X86_SYZOS_ADDR_GLOBALS;
	uint64 vmcs_addr = X86_SYZOS_ADDR_VMCS_VMCB(cpu_id, vm_id);
	uint8 error = 0; // nolint
	uint64 l2_pml4_addr = X86_SYZOS_ADDR_VM_PGTABLE(cpu_id, vm_id);
	uint64 l2_msr_bitmap = X86_SYZOS_ADDR_MSR_BITMAP(cpu_id, vm_id);
	uint64 l2_eptp_list = X86_SYZOS_ADDR_EPTP_LIST(cpu_id, vm_id);

	globals->evmcs_enabled[cpu_id][vm_id] = 0;
	nested_deactivate_evmcs_intel(cpu_id);

	*(uint32*)vmcs_addr = rdmsr(X86_MSR_IA32_VMX_BASIC);
	asm volatile("vmclear %1; setna %0"
		     : "=q"(error)
		     : "m"(vmcs_addr)
		     : "memory", "cc");
	if (error) {
		guest_uexit(0xE2BAD1);
		return;
	}
	if (!nested_vmptrld(cpu_id, vm_id))
		return;

	// Zero out critical structures.
	guest_memset((void*)l2_pml4_addr, 0, KVM_PAGE_SIZE);
	guest_memset((void*)l2_msr_bitmap, 0, KVM_PAGE_SIZE);
	guest_memset((void*)l2_eptp_list, 0, KVM_PAGE_SIZE);

	setup_l2_page_tables(CPU_VENDOR_INTEL, cpu_id, vm_id, 0);
	init_vmcs_control_fields(cpu_id, vm_id);
	init_vmcs_host_state();
	init_vmcs_guest_state(cpu_id, vm_id);
}

// Helper for setting up a segment in the VMCB
#define SETUP_L2_SEGMENT_SVM(VMBC_PTR, SEG_NAME, SELECTOR, BASE, LIMIT, ATTR) \
	vmcb_write16(VMBC_PTR, VMCB_GUEST_##SEG_NAME##_SEL, SELECTOR);        \
	vmcb_write16(VMBC_PTR, VMCB_GUEST_##SEG_NAME##_ATTR, ATTR);           \
	vmcb_write32(VMBC_PTR, VMCB_GUEST_##SEG_NAME##_LIM, LIMIT);           \
	vmcb_write64(VMBC_PTR, VMCB_GUEST_##SEG_NAME##_BASE, BASE);

GUEST_CODE static noinline void init_vmcb_guest_state(uint64 cpu_id, uint64 vm_id)
{
	uint64 vmcb_addr = X86_SYZOS_ADDR_VMCS_VMCB(cpu_id, vm_id);
	uint64 l2_code_addr = X86_SYZOS_ADDR_VM_CODE(cpu_id, vm_id);
	uint64 l2_stack_addr = X86_SYZOS_ADDR_VM_STACK(cpu_id, vm_id);
	uint64 npt_pml4_addr = X86_SYZOS_ADDR_VM_PGTABLE(cpu_id, vm_id);
	// Setup Guest Segment Registers.
	// We copy the L1 guest's segment setup, as it's a good 64-bit environment.
	SETUP_L2_SEGMENT_SVM(vmcb_addr, CS, X86_SYZOS_SEL_CODE, 0, 0xFFFFFFFF, SVM_ATTR_64BIT_CODE);
	SETUP_L2_SEGMENT_SVM(vmcb_addr, DS, X86_SYZOS_SEL_DATA, 0, 0xFFFFFFFF, SVM_ATTR_64BIT_DATA);
	SETUP_L2_SEGMENT_SVM(vmcb_addr, ES, X86_SYZOS_SEL_DATA, 0, 0xFFFFFFFF, SVM_ATTR_64BIT_DATA);
	SETUP_L2_SEGMENT_SVM(vmcb_addr, SS, X86_SYZOS_SEL_DATA, 0, 0xFFFFFFFF, SVM_ATTR_64BIT_DATA);
	SETUP_L2_SEGMENT_SVM(vmcb_addr, FS, X86_SYZOS_SEL_DATA, 0, 0xFFFFFFFF, SVM_ATTR_64BIT_DATA);
	SETUP_L2_SEGMENT_SVM(vmcb_addr, GS, X86_SYZOS_SEL_DATA, 0, 0xFFFFFFFF, SVM_ATTR_64BIT_DATA);

	// Task Register (TR). Must point to a valid, present, 64-bit TSS.
	SETUP_L2_SEGMENT_SVM(vmcb_addr, TR, X86_SYZOS_SEL_TSS64, X86_SYZOS_ADDR_VAR_TSS, 0x67, SVM_ATTR_TSS_BUSY);

	// LDT Register (LDTR) - Mark as unusable.
	// A null selector and attribute is the correct way to disable LDTR.
	SETUP_L2_SEGMENT_SVM(vmcb_addr, LDTR, 0, 0, 0, SVM_ATTR_LDTR_UNUSABLE);

	// Setup Guest Control Registers & CPU State.
	vmcb_write64(vmcb_addr, VMCB_GUEST_CR0, read_cr0() | X86_CR0_WP);
	// L2 will use L1's page tables.
	vmcb_write64(vmcb_addr, VMCB_GUEST_CR3, read_cr3());
	vmcb_write64(vmcb_addr, VMCB_GUEST_CR4, read_cr4());
	vmcb_write64(vmcb_addr, VMCB_GUEST_RIP, l2_code_addr);
	vmcb_write64(vmcb_addr, VMCB_GUEST_RSP, l2_stack_addr + KVM_PAGE_SIZE - 8);
	vmcb_write64(vmcb_addr, VMCB_GUEST_RFLAGS, RFLAGS_1_BIT);

	// Setup Guest EFER. Must have SVME, LME, and LMA for 64-bit nested.
	vmcb_write64(vmcb_addr, VMCB_GUEST_EFER, X86_EFER_LME | X86_EFER_LMA | X86_EFER_SVME);
	vmcb_write64(vmcb_addr, VMCB_RAX, 0);

	// Setup Guest Descriptor Tables.
	struct {
		uint16 limit;
		uint64 base;
	} __attribute__((packed)) gdtr, idtr;
	asm volatile("sgdt %0" : "=m"(gdtr));
	asm volatile("sidt %0" : "=m"(idtr));
	vmcb_write64(vmcb_addr, VMCB_GUEST_GDTR_BASE, gdtr.base);
	vmcb_write32(vmcb_addr, VMCB_GUEST_GDTR_LIM, gdtr.limit);
	vmcb_write64(vmcb_addr, VMCB_GUEST_IDTR_BASE, idtr.base);
	vmcb_write32(vmcb_addr, VMCB_GUEST_IDTR_LIM, idtr.limit);

	// Setup VMCB Control Fields.
	vmcb_write32(vmcb_addr, VMCB_CTRL_INTERCEPT_VEC3, VMCB_CTRL_INTERCEPT_VEC3_ALL);
	vmcb_write32(vmcb_addr, VMCB_CTRL_INTERCEPT_VEC4, VMCB_CTRL_INTERCEPT_VEC4_ALL);

	// Enable Nested Paging (NPT):
	// Write '1' to the NPT Enable field (0x090).
	vmcb_write64(vmcb_addr, VMCB_CTRL_NP_ENABLE, (1 << VMCB_CTRL_NPT_ENABLE_BIT));

	// 2Write the NPT root address to N_CR3 (0x098)
	// Unlike Intel's EPTP, AMD's N_CR3 field is *only* the
	// 4K-aligned physical address of the PML4 table.
	// It does not contain any control bits.
	uint64 npt_pointer = (npt_pml4_addr & ~0xFFF);
	vmcb_write64(vmcb_addr, VMCB_CTRL_N_CR3, npt_pointer);

	// Set Guest ASID.
	vmcb_write32(vmcb_addr, VMCB_CTRL_ASID, 1);
}

GUEST_CODE static noinline void
nested_create_vm_amd(struct api_call_1* cmd, uint64 cpu_id)
{
	uint64 vm_id = cmd->arg;
	uint64 vmcb_addr = X86_SYZOS_ADDR_VMCS_VMCB(cpu_id, vm_id);
	uint64 l2_pml4_addr = X86_SYZOS_ADDR_VM_PGTABLE(cpu_id, vm_id);
	uint64 l2_msr_bitmap = X86_SYZOS_ADDR_MSR_BITMAP(cpu_id, vm_id);

	guest_memset((void*)vmcb_addr, 0, KVM_PAGE_SIZE);
	guest_memset((void*)X86_SYZOS_ADDR_VM_ARCH_SPECIFIC(cpu_id), 0, KVM_PAGE_SIZE);
	guest_memset((void*)l2_pml4_addr, 0, KVM_PAGE_SIZE);
	guest_memset((void*)l2_msr_bitmap, 0, KVM_PAGE_SIZE);

	// Setup NPT (Nested Page Tables)
	setup_l2_page_tables(CPU_VENDOR_AMD, cpu_id, vm_id, 0);

	// Initialize VMCB Control and Guest State
	init_vmcb_guest_state(cpu_id, vm_id);
}

GUEST_CODE static noinline void
guest_handle_nested_create_vm(struct api_call_1* cmd, uint64 cpu_id)
{
	if (!nested_vm_id_valid(cmd->arg))
		return;
	if (get_cpu_vendor() == CPU_VENDOR_INTEL) {
		nested_create_vm_intel(cmd, cpu_id);
	} else {
		nested_create_vm_amd(cmd, cpu_id);
	}
}

GUEST_CODE static uint64 l2_gpa_to_pa(uint64 cpu_id, uint64 vm_id, uint64 gpa)
{
	uint64 pml4_addr = X86_SYZOS_ADDR_VM_PGTABLE(cpu_id, vm_id);
	volatile uint64* pml4 = (volatile uint64*)pml4_addr;
	uint64 pml4_idx = (gpa >> 39) & 0x1FF;
	if (!(pml4[pml4_idx] & X86_PDE64_PRESENT))
		return 0;

	volatile uint64* pdpt = (volatile uint64*)(pml4[pml4_idx] & ~0xFFF);
	uint64 pdpt_idx = (gpa >> 30) & 0x1FF;
	if (!(pdpt[pdpt_idx] & X86_PDE64_PRESENT))
		return 0;

	volatile uint64* pd = (volatile uint64*)(pdpt[pdpt_idx] & ~0xFFF);
	uint64 pd_idx = (gpa >> 21) & 0x1FF;
	if (!(pd[pd_idx] & X86_PDE64_PRESENT))
		return 0;

	volatile uint64* pt = (volatile uint64*)(pd[pd_idx] & ~0xFFF);
	uint64 pt_idx = (gpa >> 12) & 0x1FF;
	if (!(pt[pt_idx] & X86_PDE64_PRESENT))
		return 0;

	return (pt[pt_idx] & ~0xFFF) + (gpa & 0xFFF);
}

GUEST_CODE static noinline void
guest_handle_nested_load_code(struct api_call_nested_load_code* cmd, uint64 cpu_id)
{
	uint64 vm_id = cmd->vm_id;
	if (!nested_vm_id_valid(vm_id))
		return;
	// The L2 code is mapped at the user code page of this vCPU, see setup_l2_page_tables().
	uint64 l2_code_gpa = X86_SYZOS_ADDR_USER_CODE + cpu_id * KVM_PAGE_SIZE;
	// Backing address in L1 for the L2 User Code.
	uint64 l2_code_backing = l2_gpa_to_pa(cpu_id, vm_id, l2_code_gpa);
	if (!l2_code_backing) {
		guest_uexit(0xE2BAD4);
		return;
	}

	// Code size = command size - header size - vm_id size.
	uint64 l2_code_size = cmd->header.size - sizeof(struct api_call_header) - sizeof(uint64);
	if (l2_code_size > KVM_PAGE_SIZE)
		l2_code_size = KVM_PAGE_SIZE;
	guest_memcpy((void*)l2_code_backing, (void*)cmd->insns,
		     l2_code_size);

	if (get_cpu_vendor() == CPU_VENDOR_INTEL) {
		if (!nested_select_vm_intel(cpu_id, vm_id))
			return;
		// Start execution at the User Code address.
		nested_vmwrite(cpu_id, vm_id, VMCS_GUEST_RIP, l2_code_gpa);
		// Stack is mapped at X86_SYZOS_ADDR_STACK_BOTTOM
		nested_vmwrite(cpu_id, vm_id, VMCS_GUEST_RSP,
			       X86_SYZOS_ADDR_STACK_BOTTOM + KVM_PAGE_SIZE - 8);
	} else {
		vmcb_write64(X86_SYZOS_ADDR_VMCS_VMCB(cpu_id, vm_id), VMCB_GUEST_RIP, l2_code_gpa);
		vmcb_write64(X86_SYZOS_ADDR_VMCS_VMCB(cpu_id, vm_id), VMCB_GUEST_RSP, X86_SYZOS_ADDR_STACK_BOTTOM + KVM_PAGE_SIZE - 8);
	}
}

GUEST_CODE static noinline void
guest_handle_nested_load_syzos(struct api_call_nested_load_syzos* cmd, uint64 cpu_id)
{
	uint64 vm_id = cmd->vm_id;
	if (!nested_vm_id_valid(vm_id))
		return;
	uint64 prog_size = cmd->header.size - __builtin_offsetof(struct api_call_nested_load_syzos, program);
	uint64 l2_code_backing = X86_SYZOS_ADDR_VM_CODE(cpu_id, vm_id);
	volatile struct syzos_globals* globals = (volatile struct syzos_globals*)X86_SYZOS_ADDR_GLOBALS;

	if (prog_size > KVM_PAGE_SIZE)
		prog_size = KVM_PAGE_SIZE;

	// Copy Payload to Code buffer.
	guest_memcpy((void*)l2_code_backing, (void*)cmd->program, prog_size);

	// Populate Globals.
	uint64 globals_pa = l2_gpa_to_pa(cpu_id, vm_id, X86_SYZOS_ADDR_GLOBALS);
	if (!globals_pa) {
		guest_uexit(0xE2BAD3);
		return;
	}
	volatile struct syzos_globals* l2_globals = (volatile struct syzos_globals*)globals_pa;
	// L2 SYZOS runs guest_main(cpu_id), i.e. with the vCPU index of L1: this is the only user
	// code page of L2 that is backed by the VM's code buffer, and the per-vCPU memory regions
	// it may touch are those of this L1 vCPU. Note that l2_ctx[] is indexed by the L1 vCPU, so
	// only the entry of this vCPU belongs to the VM.
	uint64 vendor = get_cpu_vendor();
	l2_globals->text_sizes[cpu_id] = prog_size;
	// Pass the cached CPU vendor so L2 SYZOS handlers do not trigger CPUID VM exits.
	l2_globals->vendor = vendor;
	globals->l2_ctx[cpu_id][vm_id].rdi = cpu_id;
	globals->l2_ctx[cpu_id][vm_id].rax = 0; // Default RAX
	// Note: RSP and RIP are set in the VMCB/VMCS, but they could also be in l2_ctx
	// since the shims load them if we wanted. But currently they are in VMCB/VMCS.

	// Set RIP to guest_main.
	uint64 entry_rip = executor_fn_guest_addr(guest_main);
	if (vendor == CPU_VENDOR_INTEL) {
		if (!nested_select_vm_intel(cpu_id, vm_id))
			return;
		nested_vmwrite(cpu_id, vm_id, VMCS_GUEST_RIP, entry_rip);
		nested_vmwrite(cpu_id, vm_id, VMCS_GUEST_RSP,
			       X86_SYZOS_ADDR_STACK_BOTTOM + KVM_PAGE_SIZE - 8);
	} else {
		uint64 vmcb = X86_SYZOS_ADDR_VMCS_VMCB(cpu_id, vm_id);
		vmcb_write64(vmcb, VMCB_GUEST_RIP, entry_rip);
		vmcb_write64(vmcb, VMCB_GUEST_RSP, X86_SYZOS_ADDR_STACK_BOTTOM + KVM_PAGE_SIZE - 8);
	}
}

GUEST_CODE static noinline void
guest_handle_nested_vmentry_intel(uint64 vm_id, uint64 cpu_id, bool is_launch)
{
	volatile struct syzos_globals* globals = (volatile struct syzos_globals*)X86_SYZOS_ADDR_GLOBALS;
	struct l2_guest_regs* l2_regs = (struct l2_guest_regs*)&globals->l2_ctx[cpu_id][vm_id];
	uint64 vmx_error_code = 0;
	// 0 = success, 1 = VMfailValid (ZF=1), 2 = VMfailInvalid (CF=1).
	uint64 fail_flag = 0;
	if (!nested_select_vm_intel(cpu_id, vm_id))
		return;

	volatile struct hv_enlightened_vmcs* evmcs = NULL;
	if (globals->evmcs_enabled[cpu_id][vm_id])
		evmcs = (volatile struct hv_enlightened_vmcs*)X86_SYZOS_ADDR_EVMCS(cpu_id, vm_id);

	// Mark the VM as active on this CPU.
	globals->active_vm_id[cpu_id] = vm_id;

	asm volatile(R"(
		// 1. Red Zone protection.
		sub $128, %%rsp

		// 2. Stack Passthrough for Exit Handler.
		push %[cpu_id]
		push %[launch]

		// 3. Save L1 callee-saved registers.
		push %%rbx
		push %%rbp
		push %%r12
		push %%r13
		push %%r14
		push %%r15

		// 4. Update VMCS_HOST_RSP or evmcs->host_rsp with the current stack pointer.
		// Only mark HOST_POINTER dirty in eVMCS if host_rsp actually changed.
		test %[evmcs], %[evmcs]
		jz 4f
		cmp %%rsp, %c[host_rsp_off](%[evmcs])
		je 5f
		mov %%rsp, %c[host_rsp_off](%[evmcs])
		andl $%c[dirty_host_pointer], %c[clean_fields_off](%[evmcs])
		jmp 5f
	4:
		mov %[host_rsp_field], %%r10
		mov %%rsp, %%r11
		vmwrite %%r11, %%r10
	5:

		// 5. Load L2 GPRs from storage.
		// We use RAX as a temporary base pointer.
		mov %[l2_regs], %%rax
		mov 8(%%rax), %%rbx
		mov 16(%%rax), %%rcx
		mov 24(%%rax), %%rdx
		mov 32(%%rax), %%rsi
		mov 40(%%rax), %%rdi
		mov 48(%%rax), %%rbp
		mov 56(%%rax), %%r8
		mov 64(%%rax), %%r9
		mov 72(%%rax), %%r10
		mov 80(%%rax), %%r11
		mov 88(%%rax), %%r12
		mov 96(%%rax), %%r13
		mov 104(%%rax), %%r14
		mov 112(%%rax), %%r15
		// Finally, load RAX (L2 RAX).
		mov 0(%%rax), %%rax

		// 6. Execute Launch or Resume.
		// Check the launch flag on the stack.
		// Stack offset for 'launch': [r15][r14][r13][r12][rbp][rbx] = 6*8 = 48 bytes.
		cmpq $0, 48(%%rsp)
		je 1f
		vmlaunch
		jmp 2f

	1:	vmresume

	2:	// 7. Failure path: preserve CF before stack cleanup clobbers flags.
		mov $2, %[ret]
		jc 6f
		mov $1, %[ret]
	6:
		// Restore L1 registers to return to C.
		pop %%r15
		pop %%r14
		pop %%r13
		pop %%r12
		pop %%rbp
		pop %%rbx
		// pop launch and cpu_id
		add $16, %%rsp
		// restore Red Zone
		add $128, %%rsp
		jmp 3f

		// 8. Success path (L2 Exit).
		.globl after_vmentry_label
	after_vmentry_label:
		xor %[ret], %[ret]

	3:	// Final return to C.
	)"
		     : [ret] "=&a"(fail_flag)
		     : [launch] "r"((uint64)is_launch),
		       [host_rsp_field] "i"(VMCS_HOST_RSP),
		       [cpu_id] "r"(cpu_id),
		       [l2_regs] "r"(l2_regs),
		       [evmcs] "r"(evmcs),
		       [host_rsp_off] "i"(__builtin_offsetof(struct hv_enlightened_vmcs, host_rsp)),
		       [clean_fields_off] "i"(__builtin_offsetof(struct hv_enlightened_vmcs, hv_clean_fields)),
		       [dirty_host_pointer] "i"((int)~HV_VMX_ENLIGHTENED_CLEAN_FIELD_HOST_POINTER)
		     : "cc", "memory", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11");

	if (fail_flag) {
		// Only VMfailValid (fail_flag == 1, ZF=1) stores an instruction error field.
		if (fail_flag == 1)
			vmx_error_code = nested_vmread(cpu_id, vm_id, VMCS_VM_INSTRUCTION_ERROR);
		guest_uexit(0xE2E10000 | (uint32)vmx_error_code);
		return;
	}
}

GUEST_CODE static noinline void
guest_run_amd_vm(uint64 cpu_id, uint64 vm_id)
{
	uint64 vmcb_addr = X86_SYZOS_ADDR_VMCS_VMCB(cpu_id, vm_id);
	volatile struct syzos_globals* globals = (volatile struct syzos_globals*)X86_SYZOS_ADDR_GLOBALS;
	globals->active_vm_id[cpu_id] = vm_id;
	struct l2_guest_regs* l2_regs = (struct l2_guest_regs*)&globals->l2_ctx[cpu_id][vm_id];

	// Note: unlike VMLAUNCH/VMRESUME, VMRUN does not report failures in RFLAGS. If the VMCB is
	// invalid, VMRUN exits with VMEXIT_INVALID, which is handled by nested_vm_exit_handler_amd().
	asm volatile(R"(
		// 1. Red Zone protection.
		sub $128, %%rsp

		// 2. Stack Passthrough for Exit Handler.
		push %[cpu_id]
		// Save VMCB address for later use after VMEXIT.
		push %[vmcb_addr]

		// 3. Save L1 callee-saved registers.
		push %%rbx
		push %%rbp
		push %%r12
		push %%r13
		push %%r14
		push %%r15

		// 4. Load L2 GPRs from storage.
		mov %[l2_regs], %%rax
		// Sync RAX to VMCB (guest RAX).
		mov 0(%%rax), %%rbx
		mov %[vmcb_addr], %%rcx
		mov %%rbx, 0x5f8(%%rcx)

		mov 8(%%rax), %%rbx
		mov 16(%%rax), %%rcx
		mov 24(%%rax), %%rdx
		mov 32(%%rax), %%rsi
		mov 40(%%rax), %%rdi
		mov 48(%%rax), %%rbp
		mov 56(%%rax), %%r8
		mov 64(%%rax), %%r9
		mov 72(%%rax), %%r10
		mov 80(%%rax), %%r11
		mov 88(%%rax), %%r12
		mov 96(%%rax), %%r13
		mov 104(%%rax), %%r14
		mov 112(%%rax), %%r15

		// 4.5 Note: Host State (RSP and RIP) is saved automatically by VMRUN
		// to the HSAVE area pointed to by VM_HSAVE_PA.
		// There is no need to manually write it to the VMCB.

		// 5. Execute VMRUN.
		clgi
		// VMCB address MUST be in RAX.
		// It was pushed at Index 6: 6 * 8 = 48.
		mov 48(%%rsp), %%rax
		vmrun
	1:	// Host resumes here.
		// Restore RAX as VMRUN clobbers it.
		mov 48(%%rsp), %%rax

		// 6. Save L2's GPRs.
		// exit_code (it will be at Index 15)
		pushq 0x70(%%rax)

		// Save L2 GPRs (Index 14 down to 1).
		push %%r15
		push %%r14
		push %%r13
		push %%r12
		push %%r11
		push %%r10
		push %%r9
		push %%r8
		push %%rbp
		push %%rdi
		push %%rsi
		push %%rdx
		push %%rcx
		push %%rbx

		// Save L2 RAX from VMCB (Index 0). VMRUN does not save the guest RAX in a register, it
		// is only stored in the VMCB. RAX still holds vmcb_addr loaded after VMRUN.
		pushq 0x5f8(%%rax)

		// 7. Call the C handler.
		// arg1 (RDI) = exit reason (at Index 15: 15 * 8 = 120 bytes)
		mov 120(%%rsp), %%rdi
		// arg2 (RSI) = pointer to the saved registers
		mov %%rsp, %%rsi
		// Align RSP to 16 bytes for the C call, since RSP depends on the
		// compiler's stack frame around this inline asm.
		mov %%rsp, %%rbp
		andq $-16, %%rsp
		call nested_vm_exit_handler_amd
		mov %%rbp, %%rsp

		// 8. Restore L1 state.
		// Discard L2 GPRs (15 regs) + exit_code = 16 regs in total.
		add $128, %%rsp

		// Restore L1 callee-saved registers.
		pop %%r15
		pop %%r14
		pop %%r13
		pop %%r12
		pop %%rbp
		pop %%rbx

		// 9. Discard vmcb_addr and cpu_id.
		add $16, %%rsp

		// 10. Restore Red Zone.
		add $128, %%rsp

		stgi
		after_vmentry_label_amd:
	)"
		     :
		     : [cpu_id] "r"(cpu_id), [vmcb_addr] "r"(vmcb_addr), [l2_regs] "r"(l2_regs)
		     : "cc", "memory", "rax", "rcx", "rdx", "rsi", "rdi", "r8", "r9", "r10", "r11");
}

GUEST_CODE static noinline void
guest_handle_nested_vmlaunch(struct api_call_1* cmd, uint64 cpu_id)
{
	uint64 vm_id = cmd->arg;
	if (!nested_vm_id_valid(vm_id))
		return;
	if (get_cpu_vendor() == CPU_VENDOR_INTEL) {
		guest_handle_nested_vmentry_intel(vm_id, cpu_id, true);
	} else {
		guest_run_amd_vm(cpu_id, vm_id);
	}
}

GUEST_CODE static noinline void
guest_handle_nested_vmresume(struct api_call_1* cmd, uint64 cpu_id)
{
	uint64 vm_id = cmd->arg;
	if (!nested_vm_id_valid(vm_id))
		return;
	if (get_cpu_vendor() == CPU_VENDOR_INTEL) {
		guest_handle_nested_vmentry_intel(vm_id, cpu_id, false);
	} else {
		guest_run_amd_vm(cpu_id, vm_id);
	}
}

// Enable VMCS shadowing if advertised in IA32_VMX_PROCBASED_CTLS2 (KVM always exposes it to
// L1 and emulates shadow VMCS when hardware lacks it).
GUEST_CODE static noinline void enable_shadow_vmcs(uint64 cpu_id, uint64 vm_id)
{
	if ((rdmsr(X86_MSR_IA32_VMX_PROCBASED_CTLS2) >> 32) & SECONDARY_EXEC_SHADOW_VMCS)
		nested_vmcs_set_bits(cpu_id, vm_id, VMCS_SECONDARY_VM_EXEC_CONTROL, SECONDARY_EXEC_SHADOW_VMCS);
}

// Point VMCS_EPTP_LIST_ADDRESS at addr and enable VMFUNC[EPTP_SWITCHING] if supported by the CPU.
GUEST_CODE static noinline void enable_eptp_switching(uint64 cpu_id, uint64 vm_id, uint64 addr)
{
	if (nested_vmwrite_if_exists(cpu_id, vm_id, VMCS_EPTP_LIST_ADDRESS, addr) &&
	    nested_vmcs_field_exists(cpu_id, vm_id, VMCS_VM_FUNCTION_CONTROL)) {
		nested_vmcs_set_bits(cpu_id, vm_id, VMCS_SECONDARY_VM_EXEC_CONTROL, SECONDARY_EXEC_ENABLE_VMFUNC);
		nested_vmcs_set_bits(cpu_id, vm_id, VMCS_VM_FUNCTION_CONTROL, VMX_VMFUNC_EPTP_SWITCHING);
	}
}

GUEST_CODE static noinline void
nested_set_state_pages_intel(uint64 cpu_id, uint64 vm_id, uint64 page_type, uint64 addr)
{
	if (!nested_select_vm_intel(cpu_id, vm_id))
		return;

	// Prevent the compiler from generating a switch table.
	volatile uint64 type = page_type;
	if (type == NESTED_PAGE_APIC_ACCESS) {
		if (nested_vmwrite_if_exists(cpu_id, vm_id, VMCS_APIC_ACCESS_ADDR, addr))
			nested_vmcs_set_bits(cpu_id, vm_id, VMCS_SECONDARY_VM_EXEC_CONTROL, SECONDARY_EXEC_VIRTUALIZE_APIC_ACCESSES);
	} else if (type == NESTED_PAGE_VAPIC) {
		if (nested_vmwrite_if_exists(cpu_id, vm_id, VMCS_VIRTUAL_APIC_PAGE_ADDR, addr))
			nested_vmcs_set_bits(cpu_id, vm_id, VMCS_CPU_BASED_VM_EXEC_CONTROL, CPU_BASED_TPR_SHADOW);
	} else if (type == NESTED_PAGE_MSRPM) {
		if (nested_vmwrite_if_exists(cpu_id, vm_id, VMCS_MSR_BITMAP, addr))
			nested_vmcs_set_bits(cpu_id, vm_id, VMCS_CPU_BASED_VM_EXEC_CONTROL, CPU_BASED_USE_MSR_BITMAPS);
	} else if (type == NESTED_PAGE_IOPM) {
		// I/O bitmap B (ports 0x8000-0xffff) is placed right after bitmap A.
		if (nested_vmwrite_if_exists(cpu_id, vm_id, VMCS_IO_BITMAP_A, addr) &&
		    nested_vmwrite_if_exists(cpu_id, vm_id, VMCS_IO_BITMAP_B, addr + KVM_PAGE_SIZE))
			nested_vmcs_set_bits(cpu_id, vm_id, VMCS_CPU_BASED_VM_EXEC_CONTROL, CPU_BASED_USE_IO_BITMAPS);
	} else if (type == NESTED_PAGE_POSTED_INTR) {
		// Posted-interrupt processing requires virtual-interrupt delivery (which
		// requires the TPR shadow), external-interrupt exiting and acknowledging
		// interrupts on exit. Without these VM entry fails its control checks
		// before the descriptor is ever looked at. The notification vector is
		// left at 0, which passes the checks.
		if (nested_vmwrite_if_exists(cpu_id, vm_id, VMCS_POSTED_INTR_DESC_ADDR, addr)) {
			nested_vmcs_set_bits(cpu_id, vm_id, VMCS_PIN_BASED_VM_EXEC_CONTROL, PIN_BASED_POSTED_INTR | PIN_BASED_EXT_INTR_MASK);
			nested_vmcs_set_bits(cpu_id, vm_id, VMCS_SECONDARY_VM_EXEC_CONTROL, SECONDARY_EXEC_VIRTUAL_INTR_DELIVERY);
			nested_vmcs_set_bits(cpu_id, vm_id, VMCS_CPU_BASED_VM_EXEC_CONTROL, CPU_BASED_TPR_SHADOW);
			nested_vmcs_set_bits(cpu_id, vm_id, VMCS_VM_EXIT_CONTROLS, VM_EXIT_ACK_INTR_ON_EXIT);
		}
	} else if (type == NESTED_PAGE_PML) {
		if (nested_vmwrite_if_exists(cpu_id, vm_id, VMCS_PML_ADDRESS, addr))
			nested_vmcs_set_bits(cpu_id, vm_id, VMCS_SECONDARY_VM_EXEC_CONTROL, SECONDARY_EXEC_PAGE_MOD_LOGGING);
	} else if (type == NESTED_PAGE_EPTP_LIST) {
		// EPTP switching requires VMFUNC in secondary controls and bit 0 in
		// VM_FUNCTION_CONTROL. Skip on CPUs that do not expose VMFUNC.
		enable_eptp_switching(cpu_id, vm_id, addr);
	} else if (type == NESTED_PAGE_VMREAD_BITMAP) {
		if (nested_vmwrite_if_exists(cpu_id, vm_id, VMCS_VMREAD_BITMAP, addr))
			enable_shadow_vmcs(cpu_id, vm_id);
	} else if (type == NESTED_PAGE_VMWRITE_BITMAP) {
		if (nested_vmwrite_if_exists(cpu_id, vm_id, VMCS_VMWRITE_BITMAP, addr))
			enable_shadow_vmcs(cpu_id, vm_id);
	} else if (type == NESTED_PAGE_SHADOW_VMCS) {
		if (nested_vmcs_field_exists(cpu_id, vm_id, VMCS_VMREAD_BITMAP) &&
		    nested_vmcs_field_exists(cpu_id, vm_id, VMCS_VMWRITE_BITMAP)) {
			nested_vmwrite(cpu_id, vm_id, VMCS_LINK_POINTER, addr);
			enable_shadow_vmcs(cpu_id, vm_id);
		}
	}
}

GUEST_CODE static noinline void
nested_set_state_pages_amd(uint64 cpu_id, uint64 vm_id, uint64 page_type, uint64 addr)
{
	uint64 vmcb_addr = X86_SYZOS_ADDR_VMCS_VMCB(cpu_id, vm_id);

	// Only the MSR and I/O permission maps exist on AMD, other page types are ignored.
	// Prevent the compiler from generating a switch table.
	volatile uint64 type = page_type;
	if (type == NESTED_PAGE_MSRPM) {
		vmcb_write64(vmcb_addr, VMCB_CTRL_MSRPM_BASE_PA, addr);
		uint32 vec3 = vmcb_read32(vmcb_addr, VMCB_CTRL_INTERCEPT_VEC3);
		vec3 |= VMCB_INTERCEPT_MSR_PROT;
		vmcb_write32(vmcb_addr, VMCB_CTRL_INTERCEPT_VEC3, vec3);
	} else if (type == NESTED_PAGE_IOPM) {
		vmcb_write64(vmcb_addr, VMCB_CTRL_IOPM_BASE_PA, addr);
		uint32 vec3 = vmcb_read32(vmcb_addr, VMCB_CTRL_INTERCEPT_VEC3);
		vec3 |= VMCB_INTERCEPT_IOIO_PROT;
		vmcb_write32(vmcb_addr, VMCB_CTRL_INTERCEPT_VEC3, vec3);
	}
}

GUEST_CODE static noinline void
guest_handle_nested_set_state_pages(struct api_call_3* cmd, uint64 cpu_id)
{
	uint64 vm_id = cmd->args[0];
	uint64 page_type = cmd->args[1];
	uint64 addr = cmd->args[2];

	if (!nested_vm_id_valid(vm_id))
		return;
	if (get_cpu_vendor() == CPU_VENDOR_INTEL) {
		nested_set_state_pages_intel(cpu_id, vm_id, page_type, addr);
	} else {
		nested_set_state_pages_amd(cpu_id, vm_id, page_type, addr);
	}
}

GUEST_CODE static noinline void
guest_handle_nested_intel_vmwrite_mask(struct api_call_5* cmd, uint64 cpu_id)
{
	if (get_cpu_vendor() != CPU_VENDOR_INTEL)
		return;
	uint64 vm_id = cmd->args[0];
	if (!nested_vm_id_valid(vm_id) || !nested_select_vm_intel(cpu_id, vm_id))
		return;
	uint64 field = cmd->args[1];
	uint64 set_mask = cmd->args[2];
	uint64 unset_mask = cmd->args[3];
	uint64 flip_mask = cmd->args[4];

	// The field is chosen by the fuzzer: it may not exist on this CPU, or be read-only.
	// This is not an error in SYZOS, so do not report it as UEXIT_ASSERT.
	if (!nested_vmcs_field_exists(cpu_id, vm_id, field))
		return;
	uint64 current_value = nested_vmread(cpu_id, vm_id, field);
	uint64 new_value = (current_value & ~unset_mask) | set_mask;
	new_value ^= flip_mask;
	(void)nested_vmwrite_noassert(cpu_id, vm_id, field, new_value);
}

// VMX MSR load/store lists, see Intel SDM vol. 3C, "VM-Entry Controls for MSRs"
// and "VM-Exit Controls for MSRs".
typedef enum {
	NESTED_MSR_LIST_ENTRY_LOAD = 0, // MSRs loaded into L2 on VM entry.
	NESTED_MSR_LIST_EXIT_LOAD = 1, // MSRs loaded into L1 on VM exit.
	NESTED_MSR_LIST_EXIT_STORE = 2, // L2 MSRs stored on VM exit.
} nested_msr_list_type;

struct vmx_msr_entry {
	uint32 index;
	uint32 reserved;
	uint64 value;
};

// Append an entry to one of the VMX MSR lists of an L2 VM and point the VMCS at
// the list. The number of entries is kept in the VMCS count field itself, so
// the lists persist across VM entries and can be corrupted with
// nested_intel_vmwrite_mask. Bits 63:32 of msr end up in the reserved field,
// which must be zero for a valid entry.
GUEST_CODE static noinline void
guest_handle_nested_intel_msr_list_add(struct api_call_4* cmd, uint64 cpu_id)
{
	if (get_cpu_vendor() != CPU_VENDOR_INTEL)
		return;
	uint64 vm_id = cmd->args[0];
	uint64 msr = cmd->args[2];
	uint64 value = cmd->args[3];
	if (!nested_vm_id_valid(vm_id))
		return;

	uint64 offset = 0, addr_field = 0, count_field = 0;
	// Prevent the compiler from generating a switch table.
	volatile uint64 type = cmd->args[1];
	if (type == NESTED_MSR_LIST_ENTRY_LOAD) {
		offset = X86_SYZOS_MSR_LIST_OFFSET_ENTRY_LOAD;
		addr_field = VMCS_VM_ENTRY_MSR_LOAD_ADDR;
		count_field = VMCS_VM_ENTRY_MSR_LOAD_COUNT;
	} else if (type == NESTED_MSR_LIST_EXIT_LOAD) {
		offset = X86_SYZOS_MSR_LIST_OFFSET_EXIT_LOAD;
		addr_field = VMCS_VM_EXIT_MSR_LOAD_ADDR;
		count_field = VMCS_VM_EXIT_MSR_LOAD_COUNT;
	} else if (type == NESTED_MSR_LIST_EXIT_STORE) {
		offset = X86_SYZOS_MSR_LIST_OFFSET_EXIT_STORE;
		addr_field = VMCS_VM_EXIT_MSR_STORE_ADDR;
		count_field = VMCS_VM_EXIT_MSR_STORE_COUNT;
	} else {
		return;
	}

	if (!nested_select_vm_intel(cpu_id, vm_id))
		return;
	uint64 count = nested_vmread(cpu_id, vm_id, count_field);
	if (count >= X86_SYZOS_MSR_LIST_MAX_ENTRIES)
		return;
	uint64 list_addr = X86_SYZOS_ADDR_MSR_LISTS(cpu_id, vm_id) + offset;
	volatile struct vmx_msr_entry* entry = (volatile struct vmx_msr_entry*)list_addr + count;
	entry->index = (uint32)msr;
	entry->reserved = (uint32)(msr >> 32);
	entry->value = value;
	nested_vmwrite(cpu_id, vm_id, addr_field, list_addr);
	nested_vmwrite(cpu_id, vm_id, count_field, count + 1);
}

// The 128-bit descriptor of INVEPT (EPTP, reserved) and INVVPID (VPID, linear address).
struct vmx_invalidate_desc {
	uint64 arg;
	uint64 addr;
};

// Execute INVEPT in L1, see Intel SDM vol. 3C, "INVEPT - Invalidate Translations Derived from EPT".
// L0 handles it by dropping the shadow EPT roots that match the EPTP. The type and the EPTP are
// chosen by the fuzzer, so the instruction is allowed to fail.
GUEST_CODE static noinline void
guest_handle_nested_intel_invept(struct api_call_2* cmd)
{
	if (get_cpu_vendor() != CPU_VENDOR_INTEL)
		return;
	uint64 type = cmd->args[0];
	volatile struct vmx_invalidate_desc desc = {.arg = cmd->args[1], .addr = 0};
	asm volatile("invept %0, %1" ::"m"(desc), "r"(type) : "cc", "memory");
}

// Execute INVVPID in L1, see Intel SDM vol. 3C, "INVVPID - Invalidate Translations Based on VPID".
// The type, the VPID and the address are chosen by the fuzzer, so the instruction is allowed to
// fail.
GUEST_CODE static noinline void
guest_handle_nested_intel_invvpid(struct api_call_3* cmd)
{
	if (get_cpu_vendor() != CPU_VENDOR_INTEL)
		return;
	uint64 type = cmd->args[0];
	volatile struct vmx_invalidate_desc desc = {.arg = cmd->args[1], .addr = cmd->args[2]};
	asm volatile("invvpid %0, %1" ::"m"(desc), "r"(type) : "cc", "memory");
}

// Populate an entry of an L2 VM's VMFUNC EPTP list, point VMCS_EPTP_LIST_ADDRESS at the list,
// and enable VMFUNC[EPTP_SWITCHING] if supported by the CPU.
GUEST_CODE static noinline void
guest_handle_nested_intel_eptp_list_set(struct api_call_3* cmd, uint64 cpu_id)
{
	if (get_cpu_vendor() != CPU_VENDOR_INTEL)
		return;
	uint64 vm_id = cmd->args[0];
	uint64 index = cmd->args[1];
	uint64 eptp = cmd->args[2];
	if (!nested_vm_id_valid(vm_id) || index >= VMX_VMFUNC_EPTP_ENTRIES ||
	    !nested_select_vm_intel(cpu_id, vm_id))
		return;

	uint64 list_addr = X86_SYZOS_ADDR_EPTP_LIST(cpu_id, vm_id);
	((volatile uint64*)list_addr)[index] = eptp;
	enable_eptp_switching(cpu_id, vm_id, list_addr);
}

// Execute VMFUNC in L1 or L2, see Intel SDM vol. 3C, "VMFUNC - Invoke VM Function".
// Leaf (RAX) >= 64 raises #UD; disabled leaves, invalid EPTP list entries, or execution in L1 fail
// with #UD or a VM exit, which is expected during fuzzing.
GUEST_CODE static noinline void
guest_handle_nested_intel_vmfunc(struct api_call_2* cmd)
{
	if (get_cpu_vendor() != CPU_VENDOR_INTEL)
		return;
	uint64 func = cmd->args[0];
	uint64 index = cmd->args[1];
	asm volatile("vmfunc" : : "a"(func), "c"(index) : "memory");
}

// Execute VMREAD on the current VMCS (or L2 shadow VMCS) without switching VMPTRLD.
// Fails (CF/ZF) or causes #UD / VM exit when no VMCS is active or when trapped by the bitmap.
GUEST_CODE static noinline void
guest_handle_nested_intel_vmread(struct api_call_1* cmd)
{
	if (get_cpu_vendor() != CPU_VENDOR_INTEL)
		return;
	uint64 field = cmd->arg;
	uint64 value = 0;
	asm volatile("vmread %%rbx, %%rax" : "=a"(value) : "b"(field) : "cc");
	(void)value;
}

// Execute VMWRITE on the current VMCS (or L2 shadow VMCS) without switching VMPTRLD.
// Fails (CF/ZF) or causes #UD / VM exit when no VMCS is active or when trapped by the bitmap.
GUEST_CODE static noinline void
guest_handle_nested_intel_vmwrite(struct api_call_2* cmd)
{
	if (get_cpu_vendor() != CPU_VENDOR_INTEL)
		return;
	uint64 field = cmd->args[0];
	uint64 value = cmd->args[1];
	asm volatile("vmwrite %%rax, %%rbx" : : "a"(value), "b"(field) : "cc", "memory");
}

GUEST_CODE static noinline void
guest_handle_nested_intel_evmcs_enable(struct api_call_2* cmd, uint64 cpu_id)
{
	if (get_cpu_vendor() != CPU_VENDOR_INTEL)
		return;
	uint64 vm_id = cmd->args[0];
	uint64 flags = cmd->args[1];
	if (!nested_vm_id_valid(vm_id) ||
	    !(flags & (NESTED_EVMCS_FLAG_ENABLE | NESTED_EVMCS_FLAG_NESTED_FLUSH)))
		return;

	// Writing Hyper-V MSRs causes a #GP if Hyper-V leaves are absent in CPUID.
	if ((cpuid_eax(HV_CPUID_VENDOR_AND_MAX_FUNCTIONS) < HV_CPUID_FEATURES) ||
	    (cpuid_eax(HV_CPUID_INTERFACE) != HV_CPUID_INTERFACE_SIGNATURE) ||
	    !(cpuid_eax(HV_CPUID_FEATURES) & HV_MSR_APIC_ACCESS_AVAILABLE))
		return;

	volatile struct syzos_globals* globals = (volatile struct syzos_globals*)X86_SYZOS_ADDR_GLOBALS;
	uint64 vp_assist_gpa = X86_SYZOS_ADDR_HV_VP_ASSIST(cpu_id);
	volatile struct hv_vp_assist_page* vp_assist =
	    (volatile struct hv_vp_assist_page*)vp_assist_gpa;

	if (!globals->hv_vp_assist_enabled[cpu_id]) {
		guest_memset((void*)vp_assist_gpa, 0, KVM_PAGE_SIZE);
		vp_assist->current_nested_vmcs = ~0ULL;
		wrmsr(HV_X64_MSR_VP_ASSIST_PAGE, vp_assist_gpa | HV_X64_MSR_VP_ASSIST_PAGE_ENABLE);
		globals->hv_vp_assist_enabled[cpu_id] = 1;
	}

	uint64 evmcs_gpa = X86_SYZOS_ADDR_EVMCS(cpu_id, vm_id);
	volatile struct hv_enlightened_vmcs* evmcs =
	    (volatile struct hv_enlightened_vmcs*)evmcs_gpa;

	if (!globals->evmcs_enabled[cpu_id][vm_id]) {
		// Mirror all configured VMCS fields from this VM's regular VMCS12.
		nested_deactivate_evmcs_intel(cpu_id);
		if (!nested_vmptrld(cpu_id, vm_id))
			return;
		guest_memset((void*)evmcs_gpa, 0, KVM_PAGE_SIZE);
		evmcs->revision_id = KVM_EVMCS_VERSION;
		for (uint32 width = 0; width < 4; width++) {
			for (uint32 type = 0; type < 4; type++) {
				for (uint32 idx = 0; idx < 32; idx++) {
					uint64 field = ((uint64)width << 13) | ((uint64)type << 10) | ((uint64)idx << 1);
					uint32 desc = evmcs_field_desc(field);
					if (desc && vmcs_field_exists(field))
						evmcs_write(evmcs_gpa, field, desc, vmread(field));
				}
			}
		}
		uint64 vmcs_addr = X86_SYZOS_ADDR_VMCS_VMCB(cpu_id, vm_id);
		asm volatile("vmclear %0" : : "m"(vmcs_addr) : "memory", "cc");
		globals->evmcs_enabled[cpu_id][vm_id] = 1;
	}

	if (flags & NESTED_EVMCS_FLAG_NESTED_FLUSH) {
		// Direct L2 TLB flush hypercalls require KVM's hypercall MSR interface to be enabled.
		if (rdmsr(HV_X64_MSR_GUEST_OS_ID) == 0)
			wrmsr(HV_X64_MSR_GUEST_OS_ID, HV_LINUX_VENDOR_ID << 48);
		uint64 pa_gpa = X86_SYZOS_ADDR_HV_PARTITION_ASSIST(cpu_id);
		if (evmcs->partition_assist_page != pa_gpa)
			guest_memset((void*)pa_gpa, 0, KVM_PAGE_SIZE);
		evmcs->partition_assist_page = pa_gpa;
		evmcs->hv_vm_id = 1;
		evmcs->hv_vp_id = (uint32)cpu_id;
		evmcs->hv_enlightenments_control.nested_flush_hypercall = 1;
		evmcs->hv_clean_fields &= ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_ENLIGHTENMENTSCONTROL;
		vp_assist->nested_control.features.directhypercall = 1;
	}

	(void)nested_select_vm_intel(cpu_id, vm_id);
}

GUEST_CODE static noinline void
guest_handle_nested_intel_evmcs_write_mask(struct api_call_5* cmd, uint64 cpu_id)
{
	if (get_cpu_vendor() != CPU_VENDOR_INTEL)
		return;
	uint64 vm_id = cmd->args[0];
	volatile struct syzos_globals* globals = (volatile struct syzos_globals*)X86_SYZOS_ADDR_GLOBALS;
	if (!nested_vm_id_valid(vm_id) || !globals->evmcs_enabled[cpu_id][vm_id] ||
	    !nested_select_vm_intel(cpu_id, vm_id))
		return;

	// Prevent the compiler from generating a switch table.
	volatile uint64 field = cmd->args[1];
	volatile struct hv_enlightened_vmcs* evmcs =
	    (volatile struct hv_enlightened_vmcs*)X86_SYZOS_ADDR_EVMCS(cpu_id, vm_id);
	volatile struct hv_vp_assist_page* vp_assist =
	    (volatile struct hv_vp_assist_page*)X86_SYZOS_ADDR_HV_VP_ASSIST(cpu_id);

	uint64 addr = 0;
	uint64 width = 4;
	bool clear_enlightenments = false;
	if (field == NESTED_EVMCS_FIELD_REVISION_ID)
		addr = (uint64)&evmcs->revision_id;
	else if (field == NESTED_EVMCS_FIELD_ABORT)
		addr = (uint64)&evmcs->abort;
	else if (field == NESTED_EVMCS_FIELD_HV_CLEAN_FIELDS)
		addr = (uint64)&evmcs->hv_clean_fields;
	else if (field == NESTED_EVMCS_FIELD_HV_SYNTHETIC_CONTROLS)
		addr = (uint64)&evmcs->hv_synthetic_controls;
	else if (field == NESTED_EVMCS_FIELD_HV_ENLIGHTENMENTS_CONTROL)
		addr = (uint64)&evmcs->hv_enlightenments_control.as_uint32;
	else if (field == NESTED_EVMCS_FIELD_HV_VP_ID) {
		addr = (uint64)&evmcs->hv_vp_id;
		clear_enlightenments = true;
	} else if (field == NESTED_EVMCS_FIELD_HV_VM_ID) {
		addr = (uint64)&evmcs->hv_vm_id;
		width = 8;
		clear_enlightenments = true;
	} else if (field == NESTED_EVMCS_FIELD_PARTITION_ASSIST_PAGE) {
		addr = (uint64)&evmcs->partition_assist_page;
		width = 8;
		clear_enlightenments = true;
	} else if (field == NESTED_EVMCS_FIELD_VP_ASSIST_ENLIGHTEN_VMENTRY) {
		addr = (uint64)&vp_assist->enlighten_vmentry;
		width = 1;
	} else if (field == NESTED_EVMCS_FIELD_VP_ASSIST_CURRENT_NESTED_VMCS) {
		addr = (uint64)&vp_assist->current_nested_vmcs;
		width = 8;
	} else if (field == NESTED_EVMCS_FIELD_VP_ASSIST_NESTED_CONTROL)
		addr = (uint64)&vp_assist->nested_control.features.as_uint32;
	else if (field == NESTED_EVMCS_FIELD_PA_TLB_LOCK_COUNT)
		addr = X86_SYZOS_ADDR_HV_PARTITION_ASSIST(cpu_id);
	if (!addr)
		return;

	uint64 cur = (width == 1) ? *(volatile uint8*)addr : (width == 8) ? *(volatile uint64*)addr
									  : *(volatile uint32*)addr;
	uint64 val = ((cur & ~cmd->args[3]) | cmd->args[2]) ^ cmd->args[4];
	if (width == 1)
		*(volatile uint8*)addr = (uint8)val;
	else if (width == 8)
		*(volatile uint64*)addr = val;
	else
		*(volatile uint32*)addr = (uint32)val;
	if (clear_enlightenments)
		evmcs->hv_clean_fields &= ~HV_VMX_ENLIGHTENED_CLEAN_FIELD_ENLIGHTENMENTSCONTROL;
}

GUEST_CODE static noinline void
guest_handle_nested_amd_vmcb_write_mask(struct api_call_5* cmd, uint64 cpu_id)
{
	if (get_cpu_vendor() != CPU_VENDOR_AMD)
		return;
	uint64 vm_id = cmd->args[0];
	if (!nested_vm_id_valid(vm_id))
		return;
	uint64 vmcb_addr = X86_SYZOS_ADDR_VMCS_VMCB(cpu_id, vm_id);
	uint64 offset = cmd->args[1];
	uint64 set_mask = cmd->args[2];
	uint64 unset_mask = cmd->args[3];
	uint64 flip_mask = cmd->args[4];

	// Do not let the fuzzer write past the VMCB page.
	if (offset > KVM_PAGE_SIZE - sizeof(uint64))
		return;

	uint64 current_value = vmcb_read64((volatile uint8*)vmcb_addr, offset);
	uint64 new_value = (current_value & ~unset_mask) | set_mask;
	new_value ^= flip_mask;
	vmcb_write64(vmcb_addr, offset, new_value);
}

GUEST_CODE static noinline void
guest_handle_nested_amd_invlpga(struct api_call_2* cmd, uint64 cpu_id)
{
	if (get_cpu_vendor() != CPU_VENDOR_AMD)
		return;

	uint64 linear_addr = cmd->args[0];
	// ASID (Address Space ID) - only lower 16 bits matter usually, but register is 32-bit.
	uint32 asid = (uint32)cmd->args[1];

	asm volatile("invlpga" : : "a"(linear_addr), "c"(asid) : "memory");
}

GUEST_CODE static noinline void
guest_handle_nested_amd_stgi()
{
	if (get_cpu_vendor() != CPU_VENDOR_AMD)
		return;
	asm volatile("stgi" ::: "memory");
}

GUEST_CODE static noinline void
guest_handle_nested_amd_clgi()
{
	if (get_cpu_vendor() != CPU_VENDOR_AMD)
		return;
	asm volatile("clgi" ::: "memory");
}

GUEST_CODE static noinline void
guest_handle_nested_amd_inject_event(struct api_call_5* cmd, uint64 cpu_id)
{
	if (get_cpu_vendor() != CPU_VENDOR_AMD)
		return;

	uint64 vm_id = cmd->args[0];
	if (!nested_vm_id_valid(vm_id))
		return;
	uint64 vmcb_addr = X86_SYZOS_ADDR_VMCS_VMCB(cpu_id, vm_id);

	uint64 vector = cmd->args[1] & 0xFF;
	uint64 type = cmd->args[2] & 0x7;
	uint64 error_code = cmd->args[3] & 0xFFFFFFFF;
	uint64 flags = cmd->args[4];

	// Flags bit 0: Valid (V)
	// Flags bit 1: Error Code Valid (EV)
	uint64 event_inj = vector;
	event_inj |= (type << 8);
	if (flags & 2)
		event_inj |= (1ULL << 11); // EV bit
	if (flags & 1)
		event_inj |= (1ULL << 31); // V bit
	event_inj |= (error_code << 32);

	// EVENTINJ is at VMCB offset 0xa8, the error code (EVENTINJ_ERR) is in the upper 32 bits.
	vmcb_write64(vmcb_addr, VMCB_CTRL_EVENT_INJ, event_inj);
}

GUEST_CODE static noinline void
guest_handle_nested_amd_set_intercept(struct api_call_4* cmd, uint64 cpu_id)
{
	if (get_cpu_vendor() != CPU_VENDOR_AMD)
		return;

	uint64 vm_id = cmd->args[0];
	if (!nested_vm_id_valid(vm_id))
		return;
	uint64 vmcb_addr = X86_SYZOS_ADDR_VMCS_VMCB(cpu_id, vm_id);
	uint64 offset = cmd->args[1];
	uint64 bit_mask = cmd->args[2];
	uint64 action = cmd->args[3]; // 1 = Set, 0 = Clear

	// Only the intercept vectors can be changed: do not let the fuzzer write to the rest of the
	// VMCB or past it.
	if (offset > VMCB_CTRL_INTERCEPT_VEC5)
		return;

	// Read 32-bit intercept field (Offsets 0x00 - 0x14 are all 32-bit vectors).
	uint32 current = vmcb_read32(vmcb_addr, (uint16)offset);

	if (action == 1)
		current |= (uint32)bit_mask;
	else
		current &= ~((uint32)bit_mask);

	vmcb_write32(vmcb_addr, (uint16)offset, current);
}

GUEST_CODE static noinline void
guest_handle_nested_amd_vmload(struct api_call_1* cmd, uint64 cpu_id)
{
	if (get_cpu_vendor() != CPU_VENDOR_AMD)
		return;
	uint64 vm_id = cmd->arg;
	if (!nested_vm_id_valid(vm_id))
		return;
	uint64 vmcb_pa = X86_SYZOS_ADDR_VMCS_VMCB(cpu_id, vm_id);

	asm volatile("vmload %%rax" ::"a"(vmcb_pa) : "memory");
}

GUEST_CODE static noinline void
guest_handle_nested_amd_vmsave(struct api_call_1* cmd, uint64 cpu_id)
{
	if (get_cpu_vendor() != CPU_VENDOR_AMD)
		return;
	uint64 vm_id = cmd->arg;
	if (!nested_vm_id_valid(vm_id))
		return;
	uint64 vmcb_pa = X86_SYZOS_ADDR_VMCS_VMCB(cpu_id, vm_id);

	asm volatile("vmsave %%rax" ::"a"(vmcb_pa) : "memory");
}

#endif // EXECUTOR_COMMON_KVM_AMD64_SYZOS_H
