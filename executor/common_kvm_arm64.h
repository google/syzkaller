// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// This file is shared between executor and csource package.

// Implementation of syz_kvm_setup_cpu pseudo-syscall.
#include <sys/mman.h>

#include "common_kvm.h"
#include "kvm.h"

#if SYZ_EXECUTOR || __NR_syz_kvm_setup_cpu || __NR_syz_kvm_add_vcpu || __NR_syz_kvm_setup_syzos_vm
#include "common_kvm_arm64_syzos.h"
#endif

#if SYZ_EXECUTOR || __NR_syz_kvm_setup_cpu || __NR_syz_kvm_add_vcpu
// Register encodings from https://docs.kernel.org/virt/kvm/api.html.
#define KVM_ARM64_REGS_X0 0x6030000000100000UL
#define KVM_ARM64_REGS_X1 0x6030000000100002UL
#define KVM_ARM64_REGS_PC 0x6030000000100040UL
#define KVM_ARM64_REGS_SP_EL1 0x6030000000100044UL
#define KVM_ARM64_REGS_TPIDR_EL1 0x603000000013c684

struct kvm_text {
	uintptr_t typ;
	const void* text;
	uintptr_t size;
};

struct kvm_opt {
	uint64 typ;
	uint64 val;
};
#endif

#if SYZ_EXECUTOR || __NR_syz_kvm_setup_cpu || __NR_syz_kvm_setup_syzos_vm
struct addr_size {
	void* addr;
	size_t size;
};

static struct addr_size alloc_guest_mem(struct addr_size* free, size_t size)
{
	struct addr_size ret = {.addr = NULL, .size = 0};

	if (free->size < size)
		return ret;
	ret.addr = free->addr;
	ret.size = size;
	free->addr = (void*)((char*)free->addr + size);
	free->size -= size;
	return ret;
}

// Call KVM_SET_USER_MEMORY_REGION for the given pages.
static void vm_set_user_memory_region(int vmfd, uint32 slot, uint32 flags, uint64 guest_phys_addr, uint64 memory_size, uint64 userspace_addr)
{
	struct kvm_userspace_memory_region memreg;
	memreg.slot = slot;
	memreg.flags = flags;
	memreg.guest_phys_addr = guest_phys_addr;
	memreg.memory_size = memory_size;
	memreg.userspace_addr = userspace_addr;
	ioctl(vmfd, KVM_SET_USER_MEMORY_REGION, &memreg);
}

#define ADRP_OPCODE 0x90000000
#define ADRP_OPCODE_MASK 0x9f000000

// Code loading SyzOS into guest memory does not handle data relocations (see
// https://github.com/google/syzkaller/issues/5565), so SyzOS will crash soon after encountering an
// ADRP instruction. Detect these instructions to catch regressions early.
// The most common reason for using data relocaions is accessing global variables and constants.
// Sometimes the compiler may choose to emit a read-only constant to zero-initialize a structure
// or to generate a jump table for a switch statement.
static void validate_guest_code(void* mem, size_t size)
{
	uint32* insns = (uint32*)mem;
	for (size_t i = 0; i < size / 4; i++) {
		if ((insns[i] & ADRP_OPCODE_MASK) == ADRP_OPCODE)
			fail("ADRP instruction detected in SyzOS, exiting");
	}
}

static void install_syzos_code(void* host_mem, size_t mem_size)
{
	size_t size = (char*)&__stop_guest - (char*)&__start_guest;
	if (size > mem_size)
		fail("SyzOS size exceeds guest memory");
	memcpy(host_mem, &__start_guest, size);
	validate_guest_code(host_mem, size);
}

static void setup_vm(int vmfd, void* host_mem, void** text_slot)
{
	// Guest physical memory layout (must be in sync with executor/kvm.h):
	// 0x00000000 - unused pages
	// 0x08000000 - GICv3 distributor region (MMIO, no memory allocated)
	// 0x080a0000 - GICv3 redistributor region (MMIO, no memory allocated)
	// 0xdddd0000 - unmapped region to trigger a page faults for uexits etc. (1 page)
	// 0xdddd1000 - writable region with KVM_MEM_LOG_DIRTY_PAGES to fuzz dirty ring (2 pages)
	// 0xeeee0000 - user code (4 pages)
	// 0xeeee8000 - executor guest code (4 pages)
	// 0xeeef0000 - scratch memory for code generated at runtime (1 page)
	// 0xffff1000 - EL1 stack (1 page)
	struct addr_size allocator = {.addr = host_mem, .size = KVM_GUEST_MEM_SIZE};
	int slot = 0; // Slot numbers do not matter, they just have to be different.

	struct addr_size host_text = alloc_guest_mem(&allocator, 4 * KVM_PAGE_SIZE);
	install_syzos_code(host_text.addr, host_text.size);
	vm_set_user_memory_region(vmfd, slot++, KVM_MEM_READONLY, ARM64_ADDR_EXECUTOR_CODE, host_text.size, (uintptr_t)host_text.addr);

	struct addr_size next = alloc_guest_mem(&allocator, 2 * KVM_PAGE_SIZE);
	vm_set_user_memory_region(vmfd, slot++, KVM_MEM_LOG_DIRTY_PAGES, ARM64_ADDR_DIRTY_PAGES, next.size, (uintptr_t)next.addr);

	next = alloc_guest_mem(&allocator, KVM_MAX_VCPU * KVM_PAGE_SIZE);
	vm_set_user_memory_region(vmfd, slot++, KVM_MEM_READONLY, ARM64_ADDR_USER_CODE, next.size, (uintptr_t)next.addr);
	if (text_slot)
		*text_slot = next.addr;

	next = alloc_guest_mem(&allocator, KVM_PAGE_SIZE);
	vm_set_user_memory_region(vmfd, slot++, 0, ARM64_ADDR_EL1_STACK_BOTTOM, next.size, (uintptr_t)next.addr);

	next = alloc_guest_mem(&allocator, KVM_PAGE_SIZE);
	vm_set_user_memory_region(vmfd, slot++, 0, ARM64_ADDR_SCRATCH_CODE, next.size, (uintptr_t)next.addr);

	// Allocate memory for the ITS tables: 64K for the device table, collection table, command queue, property table,
	// plus 64K * 4 CPUs for the pending tables, and 64K * 16 devices for the ITT tables.
	int its_size = SZ_64K * (4 + 4 + 16);
	next = alloc_guest_mem(&allocator, its_size);
	vm_set_user_memory_region(vmfd, slot++, 0, ARM64_ADDR_ITS_TABLES, next.size, (uintptr_t)next.addr);

	// Map the remaining pages at address 0.
	next = alloc_guest_mem(&allocator, allocator.size);
	vm_set_user_memory_region(vmfd, slot++, 0, 0, next.size, (uintptr_t)next.addr);
}
#endif

#if SYZ_EXECUTOR || __NR_syz_kvm_setup_cpu || __NR_syz_kvm_add_vcpu
// Set the value of the specified register.
static void vcpu_set_reg(int vcpu_fd, uint64 id, uint64 val)
{
	struct kvm_one_reg reg = {.id = id, .addr = (uint64)&val};
	ioctl(vcpu_fd, KVM_SET_ONE_REG, &reg);
}

// clang-format off
// Post-processing code in pkg/csource/csource.go is very picky and requires the fail() call to be
// on a separate line.
DEFINE_GUEST_FN_TO_GPA_FN(executor_fn_guest_addr, X86_SYZOS_ADDR_EXECUTOR_CODE,
	do {
		fail("SYZOS: executor_fn_guest_addr: invalid guest address");
	} while (0))
// clang-format on

// Set up CPU registers.
static void reset_cpu_regs(int cpufd, int cpu_id, size_t text_size)
{
	// PC points to the relative offset of guest_main() within the guest code.
	vcpu_set_reg(cpufd, KVM_ARM64_REGS_PC, executor_fn_guest_addr((uintptr_t)guest_main));
	vcpu_set_reg(cpufd, KVM_ARM64_REGS_SP_EL1, ARM64_ADDR_EL1_STACK_BOTTOM + KVM_PAGE_SIZE - 128);
	// Store the CPU ID in TPIDR_EL1.
	vcpu_set_reg(cpufd, KVM_ARM64_REGS_TPIDR_EL1, cpu_id);
	// Pass parameters to guest_main().
	vcpu_set_reg(cpufd, KVM_ARM64_REGS_X0, text_size);
	vcpu_set_reg(cpufd, KVM_ARM64_REGS_X1, cpu_id);
}

static void install_user_code(int cpufd, void* user_text_slot, int cpu_id, const void* text, size_t text_size)
{
	if ((cpu_id < 0) || (cpu_id >= KVM_MAX_VCPU))
		return;
	if (!user_text_slot)
		return;
	if (text_size > KVM_PAGE_SIZE)
		text_size = KVM_PAGE_SIZE;
	void* target = (void*)((uint64)user_text_slot + (KVM_PAGE_SIZE * cpu_id));
	memcpy(target, text, text_size);
	reset_cpu_regs(cpufd, cpu_id, text_size);
}

static void setup_cpu_with_opts(int vmfd, int cpufd, const struct kvm_opt* opt, int opt_count)
{
	uint32 features = 0;
	if (opt_count > 1)
		opt_count = 1;
	for (int i = 0; i < opt_count; i++) {
		uint64 typ = opt[i].typ;
		uint64 val = opt[i].val;
		switch (typ) {
		case 1:
			features = val;
			break;
		}
	}

	struct kvm_vcpu_init init;
	// Queries KVM for preferred CPU target type.
	ioctl(vmfd, KVM_ARM_PREFERRED_TARGET, &init);
	init.features[0] = features;
	// Use the modified struct kvm_vcpu_init to initialize the virtual CPU.
	ioctl(cpufd, KVM_ARM_VCPU_INIT, &init);
}

#endif

#if SYZ_EXECUTOR || __NR_syz_kvm_setup_cpu
// syz_kvm_setup_cpu(fd fd_kvmvm, cpufd fd_kvmcpu, usermem vma[24], text ptr[in, array[kvm_text, 1]], ntext len[text], flags flags[kvm_setup_flags], opts ptr[in, array[kvm_setup_opt, 0:2]], nopt len[opts])
static volatile long syz_kvm_setup_cpu(volatile long a0, volatile long a1, volatile long a2, volatile long a3, volatile long a4, volatile long a5, volatile long a6, volatile long a7)
{
	const int vmfd = a0;
	const int cpufd = a1;
	void* const host_mem = (void*)a2;
	const struct kvm_text* const text_array_ptr = (struct kvm_text*)a3;
	const uintptr_t text_count = a4;
	const uintptr_t flags = a5;
	const struct kvm_opt* const opt_array_ptr = (struct kvm_opt*)a6;
	uintptr_t opt_count = a7;

	(void)flags;
	(void)opt_count;

	(void)text_count; // fuzzer can spoof count and we need just 1 text, so ignore text_count
	int text_type = text_array_ptr[0].typ;
	const void* text = text_array_ptr[0].text;
	size_t text_size = text_array_ptr[0].size;
	(void)text_type;

	void* user_text_slot = NULL;
	setup_vm(vmfd, host_mem, &user_text_slot);
	setup_cpu_with_opts(vmfd, cpufd, opt_array_ptr, opt_count);

	// Assume CPU is 0.
	install_user_code(cpufd, user_text_slot, 0, text, text_size);
	return 0;
}
#endif

#if SYZ_EXECUTOR || __NR_syz_kvm_setup_syzos_vm || __NR_syz_kvm_add_vcpu
struct kvm_syz_vm {
	int vmfd;
	int next_cpu_id;
	void* user_text;
};
#endif

#if SYZ_EXECUTOR || __NR_syz_kvm_setup_syzos_vm

static long syz_kvm_setup_syzos_vm(volatile long a0, volatile long a1)
{
	const int vmfd = a0;
	void* host_mem = (void*)a1;

	void* user_text_slot = NULL;
	struct kvm_syz_vm* ret = (struct kvm_syz_vm*)host_mem;
	host_mem = (void*)((uint64)host_mem + KVM_PAGE_SIZE);
	setup_vm(vmfd, host_mem, &user_text_slot);
	ret->vmfd = vmfd;
	ret->next_cpu_id = 0;
	ret->user_text = user_text_slot;
	return (long)ret;
}
#endif

#if SYZ_EXECUTOR || __NR_syz_kvm_add_vcpu
static long syz_kvm_add_vcpu(volatile long a0, volatile long a1, volatile long a2, volatile long a3)
{
	struct kvm_syz_vm* vm = (struct kvm_syz_vm*)a0;
	struct kvm_text* utext = (struct kvm_text*)a1;
	const void* text = utext->text;
	size_t text_size = utext->size;
	const struct kvm_opt* const opt_array_ptr = (struct kvm_opt*)a2;
	uintptr_t opt_count = a3;

	if (!vm) {
		errno = EINVAL;
		return -1;
	}
	if (vm->next_cpu_id == KVM_MAX_VCPU) {
		errno = ENOMEM;
		return -1;
	}
	int cpu_id = vm->next_cpu_id;
	int cpufd = ioctl(vm->vmfd, KVM_CREATE_VCPU, cpu_id);
	if (cpufd == -1)
		return -1;
	// Only increment next_cpu_id if CPU creation succeeded.
	vm->next_cpu_id++;
	setup_cpu_with_opts(vm->vmfd, cpufd, opt_array_ptr, opt_count);
	install_user_code(cpufd, vm->user_text, cpu_id, text, text_size);
	return cpufd;
}
#endif

#if SYZ_EXECUTOR || __NR_syz_kvm_vgic_v3_setup
static int kvm_set_device_attr(int dev_fd, uint32 group, uint64 attr, void* val)
{
	struct kvm_device_attr kvmattr = {
	    .flags = 0,
	    .group = group,
	    .attr = attr,
	    .addr = (uintptr_t)val,
	};

	return ioctl(dev_fd, KVM_SET_DEVICE_ATTR, &kvmattr);
}

static int kvm_create_device(int vm_fd, int type)
{
	struct kvm_create_device create_dev = {
	    .type = (uint32)type,
	    .fd = (uint32)-1,
	    .flags = 0,
	};

	if (ioctl(vm_fd, KVM_CREATE_DEVICE, &create_dev) != -1)
		return create_dev.fd;
	else
		return -1;
}

#define REDIST_REGION_ATTR_ADDR(count, base, flags, index) \
	(((uint64)(count) << 52) |                         \
	 ((uint64)((base) >> 16) << 16) |                  \
	 ((uint64)(flags) << 12) |                         \
	 index)

// Set up the VGICv3 interrupt controller.
// syz_kvm_vgic_v3_setup(fd fd_kvmvm, ncpus flags[kvm_num_cpus], nirqs flags[kvm_num_irqs])
static long syz_kvm_vgic_v3_setup(volatile long a0, volatile long a1, volatile long a2)
{
	const int vm_fd = a0;
	const int nr_vcpus = a1;
	const int want_nr_irq = a2;

	int vgic_fd = kvm_create_device(vm_fd, KVM_DEV_TYPE_ARM_VGIC_V3);
	if (vgic_fd == -1)
		return -1;

	uint32 nr_irq = want_nr_irq;
	int ret = kvm_set_device_attr(vgic_fd, KVM_DEV_ARM_VGIC_GRP_NR_IRQS, 0, &nr_irq);
	if (ret == -1) {
		close(vgic_fd);
		return -1;
	}

	uint64 gicd_base_gpa = ARM64_ADDR_GICD_BASE;
	ret = kvm_set_device_attr(vgic_fd, KVM_DEV_ARM_VGIC_GRP_ADDR, KVM_VGIC_V3_ADDR_TYPE_DIST, &gicd_base_gpa);
	if (ret == -1) {
		close(vgic_fd);
		return -1;
	}
	uint64 redist_attr = REDIST_REGION_ATTR_ADDR(nr_vcpus, ARM64_ADDR_GICR_BASE, 0, 0);
	ret = kvm_set_device_attr(vgic_fd, KVM_DEV_ARM_VGIC_GRP_ADDR, KVM_VGIC_V3_ADDR_TYPE_REDIST_REGION, &redist_attr);
	if (ret == -1) {
		close(vgic_fd);
		return -1;
	}

	ret = kvm_set_device_attr(vgic_fd, KVM_DEV_ARM_VGIC_GRP_CTRL, KVM_DEV_ARM_VGIC_CTRL_INIT, NULL);
	if (ret == -1) {
		close(vgic_fd);
		return -1;
	}

	return vgic_fd;
}
#endif

#if SYZ_EXECUTOR || __NR_syz_kvm_assert_syzos_uexit
static long syz_kvm_assert_syzos_uexit(volatile long a0, volatile long a1)
{
	struct kvm_run* run = (struct kvm_run*)a0;
	uint64 expect = a1;

	if (!run || (run->exit_reason != KVM_EXIT_MMIO) || (run->mmio.phys_addr != ARM64_ADDR_UEXIT)) {
		errno = EINVAL;
		return -1;
	}

	if ((((uint64*)(run->mmio.data))[0]) != expect) {
		errno = EDOM;
		return -1;
	}
	return 0;
}
#endif

#if SYZ_EXECUTOR || __NR_syz_kvm_assert_reg
static long syz_kvm_assert_reg(volatile long a0, volatile long a1, volatile long a2)
{
	int vcpu_fd = (int)a0;
	uint64 id = (uint64)a1;
	uint64 expect = a2, val = 0;

	struct kvm_one_reg reg = {.id = id, .addr = (uint64)&val};
	int ret = ioctl(vcpu_fd, KVM_GET_ONE_REG, &reg);
	if (ret)
		return ret;
	if (val != expect) {
		errno = EDOM;
		return -1;
	}
	return 0;
}
#endif
