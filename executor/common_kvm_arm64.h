// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// This file is shared between executor and csource package.

// Implementation of syz_kvm_setup_cpu pseudo-syscall.

#include "common_kvm_arm64_syzos.h"
#include "kvm.h"

// Register encodings from https://docs.kernel.org/virt/kvm/api.html.
#define KVM_ARM64_REGS_X0 0x6030000000100000UL
#define KVM_ARM64_REGS_PC 0x6030000000100040UL
#define KVM_ARM64_REGS_SP_EL1 0x6030000000100044UL

struct kvm_text {
	uintptr_t typ;
	const void* text;
	uintptr_t size;
};

struct kvm_opt {
	uint64 typ;
	uint64 val;
};

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

// Set the value of the specified register.
static void vcpu_set_reg(int vcpu_fd, uint64 id, uint64 val)
{
	struct kvm_one_reg reg = {.id = id, .addr = (uint64)&val};
	ioctl(vcpu_fd, KVM_SET_ONE_REG, &reg);
}

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

struct api_fn {
	int index;
	void* fn;
};

// syz_kvm_setup_cpu(fd fd_kvmvm, cpufd fd_kvmcpu, usermem vma[24], text ptr[in, array[kvm_text, 1]], ntext len[text], flags flags[kvm_setup_flags], opts ptr[in, array[kvm_setup_opt, 0:2]], nopt len[opts])
static volatile long syz_kvm_setup_cpu(volatile long a0, volatile long a1, volatile long a2, volatile long a3, volatile long a4, volatile long a5, volatile long a6, volatile long a7)
{
	const int vmfd = a0;
	const int cpufd = a1;
	char* const host_mem = (char*)a2;
	const struct kvm_text* const text_array_ptr = (struct kvm_text*)a3;
	const uintptr_t text_count = a4;
	const uintptr_t flags = a5;
	const struct kvm_opt* const opt_array_ptr = (struct kvm_opt*)a6;
	uintptr_t opt_count = a7;

	(void)flags;
	(void)opt_count;

	const uintptr_t page_size = 4 << 10;
	const uintptr_t guest_mem_size = 24 * page_size;

	(void)text_count; // fuzzer can spoof count and we need just 1 text, so ignore text_count
	int text_type = text_array_ptr[0].typ;
	const void* text = text_array_ptr[0].text;
	size_t text_size = text_array_ptr[0].size;
	(void)text_type;
	(void)opt_array_ptr;

	uint32 features = 0;
	if (opt_count > 1)
		opt_count = 1;
	for (uintptr_t i = 0; i < opt_count; i++) {
		uint64 typ = opt_array_ptr[i].typ;
		uint64 val = opt_array_ptr[i].val;
		switch (typ) {
		case 1:
			features = val;
			break;
		}
	}

	// Guest physical memory layout:
	// 0x00000000 - unused pages
	// 0xdddd0000 - unmapped region to trigger a page faults for uexits etc. (1 page)
	// 0xeeee0000 - user code (1 page)
	// 0xeeee8000 - executor guest code (4 pages)
	// 0xffff1000 - EL1 stack (1 page)
	struct addr_size allocator = {.addr = host_mem, .size = guest_mem_size};
	int slot = 0; // Slot numbers do not matter, they just have to be different.

	struct addr_size host_text = alloc_guest_mem(&allocator, 4 * page_size);
	memcpy(host_text.addr, &__start_guest, (char*)&__stop_guest - (char*)&__start_guest);
	vm_set_user_memory_region(vmfd, slot++, KVM_MEM_READONLY, ARM64_ADDR_EXECUTOR_CODE, host_text.size, (uintptr_t)host_text.addr);

	struct addr_size next = alloc_guest_mem(&allocator, page_size);
	if (text_size > next.size)
		text_size = next.size;
	memcpy(next.addr, text, text_size);
	vm_set_user_memory_region(vmfd, slot++, KVM_MEM_READONLY, ARM64_ADDR_USER_CODE, next.size, (uintptr_t)next.addr);

	next = alloc_guest_mem(&allocator, page_size);
	vm_set_user_memory_region(vmfd, slot++, 0, ARM64_ADDR_EL1_STACK_BOTTOM, next.size, (uintptr_t)next.addr);

	// Map the remaining pages at address 0.
	next = alloc_guest_mem(&allocator, allocator.size);
	vm_set_user_memory_region(vmfd, slot++, 0, 0, next.size, (uintptr_t)next.addr);

	struct kvm_vcpu_init init;
	// Queries KVM for preferred CPU target type.
	ioctl(vmfd, KVM_ARM_PREFERRED_TARGET, &init);
	init.features[0] = features;
	// Use the modified struct kvm_vcpu_init to initialize the virtual CPU.
	ioctl(cpufd, KVM_ARM_VCPU_INIT, &init);

	// Set up CPU registers.
	// PC points to the relative offset of guest_main() within the guest code.
	vcpu_set_reg(cpufd, KVM_ARM64_REGS_PC, ARM64_ADDR_EXECUTOR_CODE + ((uint64)guest_main - (uint64)&__start_guest));
	vcpu_set_reg(cpufd, KVM_ARM64_REGS_SP_EL1, ARM64_ADDR_EL1_STACK_BOTTOM + page_size - 128);
	// Pass parameters to guest_main().
	vcpu_set_reg(cpufd, KVM_ARM64_REGS_X0, text_size);

	return 0;
}
