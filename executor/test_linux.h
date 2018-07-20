// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#include <sys/utsname.h>

static unsigned host_kernel_version();
static void dump_cpu_state(int cpufd, char* vm_mem);

static int test_one(int text_type, const char* text, int text_size, int flags, unsigned reason, bool check_rax)
{
	printf("=== testing text %d, text size 0x%x, flags 0x%x\n", text_type, text_size, flags);
	int kvmfd = open("/dev/kvm", O_RDWR);
	if (kvmfd == -1) {
		if (errno == ENOENT) {
			printf("/dev/kvm is not present\n");
			return -1;
		}
		if (errno == EPERM || errno == EACCES) {
			printf("no permissions to open /dev/kvm\n");
			return -1;
		}
		printf("failed to open /dev/kvm (%d)\n", errno);
		return 1;
	}
	int vmfd = ioctl(kvmfd, KVM_CREATE_VM, 0);
	if (vmfd == -1) {
		printf("KVM_CREATE_VM failed (%d)\n", errno);
		return 1;
	}
	int cpufd = ioctl(vmfd, KVM_CREATE_VCPU, 0);
	if (cpufd == -1) {
		printf("KVM_CREATE_VCPU failed (%d)\n", errno);
		return 1;
	}
	int cpu_mem_size = ioctl(kvmfd, KVM_GET_VCPU_MMAP_SIZE, 0);
	if (cpu_mem_size <= 0) {
		printf("KVM_GET_VCPU_MMAP_SIZE failed (%d)\n", errno);
		return 1;
	}
	struct kvm_run* cpu_mem = (struct kvm_run*)mmap(0, cpu_mem_size,
							PROT_READ | PROT_WRITE, MAP_SHARED, cpufd, 0);
	if (cpu_mem == MAP_FAILED) {
		printf("cpu mmap failed (%d)\n", errno);
		return 1;
	}
	int vm_mem_size = 96 << 10;
	void* vm_mem = mmap(0, vm_mem_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	if (vm_mem == MAP_FAILED) {
		printf("mmap failed (%d)\n", errno);
		return 1;
	}
	struct kvm_text kvm_text;
	kvm_text.typ = text_type;
	kvm_text.text = text;
	kvm_text.size = text_size;
	if (syz_kvm_setup_cpu(vmfd, cpufd, (uintptr_t)vm_mem, (uintptr_t)&kvm_text, 1, flags, 0, 0)) {
		printf("syz_kvm_setup_cpu failed (%d)\n", errno);
		return 1;
	}
	if (ioctl(cpufd, KVM_RUN, 0)) {
		printf("KVM_RUN failed (%d)\n", errno);
		return 1;
	}
	struct kvm_regs regs;
	if (ioctl(cpufd, KVM_GET_REGS, &regs)) {
		printf("KVM_GET_REGS failed (%d)\n", errno);
		dump_cpu_state(cpufd, (char*)vm_mem);
		return 1;
	}
	if (cpu_mem->exit_reason != reason) {
		printf("KVM_RUN exit reason %d, expect %d\n", cpu_mem->exit_reason, reason);
		if (cpu_mem->exit_reason == KVM_EXIT_FAIL_ENTRY)
			printf("hardware exit reason 0x%llx\n",
			       cpu_mem->fail_entry.hardware_entry_failure_reason);
		dump_cpu_state(cpufd, (char*)vm_mem);
		return 1;
	}
	if (check_rax && regs.rax != 0xbadc0de) {
		printf("wrong result: rax=0x%llx\n", (long long)regs.rax);
		dump_cpu_state(cpufd, (char*)vm_mem);
		return 1;
	}
	munmap(vm_mem, vm_mem_size);
	munmap(cpu_mem, cpu_mem_size);
	close(cpufd);
	close(vmfd);
	close(kvmfd);
	return 0;
}

static int test_kvm()
{
	int res;

	unsigned ver = host_kernel_version();
	printf("host kernel version %u\n", ver);

	// TODO: test VM mode.
	//const char text16_vm[] = "\x48\xc7\xc3\xde\xc0\xad\x0b\x90\x90\x48\xc7\xc0\xef\xcd\xab\x00\xf4";
	//if (res = test_one(64, text16_vm, sizeof(text16_vm) - 1, KVM_SETUP_VM, KVM_EXIT_HLT, true))
	//	return res;

	/// TODO: test code executed in interrupt handlers.
	//const char text32_div0[] = "\x31\xc0\xf7\xf0";
	//if (res = test_one(32, text32_div0, sizeof(text32_div0)-1, 0, KVM_EXIT_HLT, true))
	//	return res;

	const char text8[] = "\x66\xb8\xde\xc0\xad\x0b";
	if ((res = test_one(8, text8, sizeof(text8) - 1, 0, KVM_EXIT_HLT, true)))
		return res;
	if ((res = test_one(8, text8, sizeof(text8) - 1, KVM_SETUP_VIRT86, KVM_EXIT_SHUTDOWN, true)))
		return res;
	if ((res = test_one(8, text8, sizeof(text8) - 1, KVM_SETUP_VIRT86 | KVM_SETUP_PAGING, KVM_EXIT_SHUTDOWN, true)))
		return res;

	const char text16[] = "\x66\xb8\xde\xc0\xad\x0b";
	if ((res = test_one(16, text16, sizeof(text16) - 1, 0, KVM_EXIT_HLT, true)))
		return res;
	if ((res = test_one(16, text16, sizeof(text16) - 1, KVM_SETUP_CPL3, KVM_EXIT_SHUTDOWN, true)))
		return res;

	const char text32[] = "\xb8\xde\xc0\xad\x0b";
	if ((res = test_one(32, text32, sizeof(text32) - 1, 0, KVM_EXIT_HLT, true)))
		return res;
	if ((res = test_one(32, text32, sizeof(text32) - 1, KVM_SETUP_PAGING, KVM_EXIT_HLT, true)))
		return res;
	if ((res = test_one(32, text32, sizeof(text32) - 1, KVM_SETUP_CPL3, KVM_EXIT_SHUTDOWN, true)))
		return res;

	const char text64[] = "\x90\xb8\xde\xc0\xad\x0b";
	if ((res = test_one(64, text64, sizeof(text64) - 1, 0, KVM_EXIT_HLT, true)))
		return res;
	if ((res = test_one(64, text64, sizeof(text64) - 1, KVM_SETUP_PAGING, KVM_EXIT_HLT, true)))
		return res;
	if ((res = test_one(64, text64, sizeof(text64) - 1, KVM_SETUP_CPL3, KVM_EXIT_SHUTDOWN, true)))
		return res;

	const char text64_sysenter[] = "\xb8\xde\xc0\xad\x0b\x0f\x34";
	if ((res = test_one(64, text64_sysenter, sizeof(text64_sysenter) - 1, KVM_SETUP_CPL3, KVM_EXIT_SHUTDOWN, true)))
		return res;

	// Note: SMM does not work on 3.13 kernels.
	if (ver >= 404) {
		const char text8_smm[] = "\x66\xb8\xde\xc0\xad\x0b";
		if ((res = test_one(8, text8_smm, sizeof(text8_smm) - 1, KVM_SETUP_SMM, KVM_EXIT_HLT, true)))
			return res;
		if ((res = test_one(8, text8_smm, sizeof(text8_smm) - 1, KVM_SETUP_SMM | KVM_SETUP_PROTECTED, KVM_EXIT_HLT, true)))
			return res;

		//const char text32_smm[] = "\xb8\xde\xc0\xad\x0b";
		if ((res = test_one(32, text8_smm, sizeof(text8_smm) - 1, KVM_SETUP_SMM, KVM_EXIT_HLT, true)))
			return res;

		// Also ensure that we are actually in SMM.
		// If we do MOV to RAX and then RSM, RAX will be restored to host value so RAX check will fail.
		// So instead we execute just RSM, if we are in SMM we will get KVM_EXIT_HLT,
		// otherwise KVM_EXIT_INTERNAL_ERROR.
		const char text_rsm[] = "\x0f\xaa";
		if ((res = test_one(8, text_rsm, sizeof(text_rsm) - 1, KVM_SETUP_SMM, KVM_EXIT_HLT, false)))
			return res;
		if ((res = test_one(32, text_rsm, sizeof(text_rsm) - 1, KVM_SETUP_SMM, KVM_EXIT_HLT, false)))
			return res;
	}

	return 0;
}

static unsigned host_kernel_version()
{
	struct utsname name;
	if (uname(&name)) {
		printf("uname failed (%d)\n", errno);
		doexit(1);
	}
	unsigned major = atoi(name.release);
	unsigned minor = 0;
	if (strchr(name.release, '.'))
		minor = atoi(strchr(name.release, '.') + 1);
	return major * 100 + minor;
}

static void dump_seg(const char* name, struct kvm_segment* seg)
{
	printf("%s: base=0x%llx limit=0x%x sel=0x%x type=%d p=%d dpl=%d, db=%d s=%d l=%d g=%d\n",
	       name, seg->base, seg->limit, seg->selector, seg->type, seg->present, seg->dpl, seg->db, seg->s, seg->l, seg->g);
}

static void dump_cpu_state(int cpufd, char* vm_mem)
{
	struct kvm_sregs sregs;
	if (ioctl(cpufd, KVM_GET_SREGS, &sregs)) {
		printf("KVM_GET_SREGS failed (%d)\n", errno);
		return;
	}
	struct kvm_regs regs;
	if (ioctl(cpufd, KVM_GET_REGS, &regs)) {
		printf("KVM_GET_REGS failed (%d)\n", errno);
		return;
	}
	printf("RIP=0x%llx RAX=0x%llx RDX=0x%llx RCX=0x%llx RBX=0x%llx CF=%d ZF=%d\n",
	       regs.rip, regs.rax, regs.rdx, regs.rcx, regs.rbx, !!(regs.rflags & (1 << 0)), !!(regs.rflags & (1 << 6)));
	printf("CR0=0x%llx CR2=0x%llx CR4=0x%llx EFER=0x%llx\n",
	       sregs.cr0, sregs.cr2, sregs.cr4, sregs.efer);
	dump_seg("CS", &sregs.cs);
	dump_seg("SS", &sregs.ss);
	dump_seg("DS", &sregs.ds);

	if (false) {
		printf("memory:\n");
		for (int i = 0; i < 0x80; i++)
			printf("0x%02x: 0x%02x\n", i, ((unsigned char*)vm_mem)[i]);
	}

	if (false) {
		printf("vmcs:\n");
		const int vmcs_size = 0x1000;
		for (int i = 0; i < vmcs_size / 8; i += 4) {
			printf("0x%04x: 0x%016llx 0x%016llx 0x%016llx 0x%016llx\n", i,
			       ((long long*)vm_mem)[i], ((long long*)vm_mem)[i + 1], ((long long*)vm_mem)[i + 2], ((long long*)vm_mem)[i + 3]);
		}
	}
}
