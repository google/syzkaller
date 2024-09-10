// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// This file is shared between executor and csource package.

// Implementation of syz_kvm_setup_cpu pseudo-syscall.

#include "kvm.h"

#if SYZ_EXECUTOR || __NR_syz_kvm_setup_cpu

// Register encodings from https://docs.kernel.org/virt/kvm/api.html.
#define KVM_ARM64_REGS_X0 0x6030000000100000UL
#define KVM_ARM64_REGS_PC 0x6030000000100040UL
#define KVM_ARM64_REGS_SP_EL1 0x6030000000100044UL

#include "common_kvm_arm64_syzos.h"
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

	// Guest physical memory layout (must be in sync with executor/kvm.h):
	// 0x00000000 - unused pages
	// 0x08000000 - GICv3 distributor region (MMIO, no memory allocated)
	// 0x080a0000 - GICv3 redistributor region (MMIO, no memory allocated)
	// 0xdddd0000 - unmapped region to trigger a page faults for uexits etc. (1 page)
	// 0xdddd1000 - writable region with KVM_MEM_LOG_DIRTY_PAGES to fuzz dirty ring (2 pages)
	// 0xeeee0000 - user code (1 page)
	// 0xeeee8000 - executor guest code (4 pages)
	// 0xeeef0000 - scratch memory for code generated at runtime (1 page)
	// 0xffff1000 - EL1 stack (1 page)
	struct addr_size allocator = {.addr = host_mem, .size = guest_mem_size};
	int slot = 0; // Slot numbers do not matter, they just have to be different.

	struct addr_size host_text = alloc_guest_mem(&allocator, 4 * page_size);
	memcpy(host_text.addr, &__start_guest, (char*)&__stop_guest - (char*)&__start_guest);
	vm_set_user_memory_region(vmfd, slot++, KVM_MEM_READONLY, ARM64_ADDR_EXECUTOR_CODE, host_text.size, (uintptr_t)host_text.addr);

	struct addr_size next = alloc_guest_mem(&allocator, 2 * page_size);
	vm_set_user_memory_region(vmfd, slot++, KVM_MEM_LOG_DIRTY_PAGES, ARM64_ADDR_DIRTY_PAGES, next.size, (uintptr_t)next.addr);

	next = alloc_guest_mem(&allocator, page_size);
	if (text_size > next.size)
		text_size = next.size;
	memcpy(next.addr, text, text_size);
	vm_set_user_memory_region(vmfd, slot++, KVM_MEM_READONLY, ARM64_ADDR_USER_CODE, next.size, (uintptr_t)next.addr);

	next = alloc_guest_mem(&allocator, page_size);
	vm_set_user_memory_region(vmfd, slot++, 0, ARM64_ADDR_EL1_STACK_BOTTOM, next.size, (uintptr_t)next.addr);

	next = alloc_guest_mem(&allocator, page_size);
	vm_set_user_memory_region(vmfd, slot++, 0, ARM64_ADDR_SCRATCH_CODE, next.size, (uintptr_t)next.addr);

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
