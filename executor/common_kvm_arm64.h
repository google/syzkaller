// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// This file is shared between executor and csource package.

// Implementation of syz_kvm_setup_cpu pseudo-syscall.

struct kvm_text {
	uintptr_t typ;
	const void* text;
	uintptr_t size;
};

struct kvm_opt {
	uint64 typ;
	uint64 val;
};

// syz_kvm_setup_cpu(fd fd_kvmvm, cpufd fd_kvmcpu, usermem vma[24], text ptr[in, array[kvm_text, 1]], ntext len[text], flags flags[kvm_setup_flags], opts ptr[in, array[kvm_setup_opt, 0:2]], nopt len[opts])
static long syz_kvm_setup_cpu(volatile long a0, volatile long a1, volatile long a2, volatile long a3, volatile long a4, volatile long a5, volatile long a6, volatile long a7)
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
	const uintptr_t guest_mem = 0;
	const uintptr_t guest_mem_size = 24 * page_size;

	(void)text_count; // fuzzer can spoof count and we need just 1 text, so ignore text_count
	int text_type = 0;
	const void* text = 0;
	int text_size = 0;
	NONFAILING(text_type = text_array_ptr[0].typ);
	NONFAILING(text = text_array_ptr[0].text);
	NONFAILING(text_size = text_array_ptr[0].size);
	(void)text_type;
	(void)opt_array_ptr;

	uint32 features = 0;
	if (opt_count > 1)
		opt_count = 1;
	uintptr_t i;
	for (i = 0; i < opt_count; i++) {
		uint64 typ = 0;
		uint64 val = 0;
		NONFAILING(typ = opt_array_ptr[i].typ);
		NONFAILING(val = opt_array_ptr[i].val);
		switch (typ) {
		case 1:
			features = val;
			break;
		}
	}

	for (i = 0; i < guest_mem_size / page_size; i++) {
		struct kvm_userspace_memory_region memreg;
		memreg.slot = i;
		memreg.flags = 0; // can be KVM_MEM_LOG_DIRTY_PAGES | KVM_MEM_READONLY
		memreg.guest_phys_addr = guest_mem + i * page_size;
		memreg.memory_size = page_size;
		memreg.userspace_addr = (uintptr_t)host_mem + i * page_size;
		ioctl(vmfd, KVM_SET_USER_MEMORY_REGION, &memreg);
	}

	struct kvm_vcpu_init init;
	ioctl(cpufd, KVM_ARM_PREFERRED_TARGET, &init);
	init.features[0] = features;
	ioctl(cpufd, KVM_ARM_VCPU_INIT, &init);

	if (text_size > 1000)
		text_size = 1000;
	NONFAILING(memcpy(host_mem, text, text_size));

	return 0;
}
