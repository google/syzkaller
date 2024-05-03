// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/syscall.h>
#include <unistd.h>

const unsigned long KCOV_TRACE_PC = 0;
const unsigned long KCOV_TRACE_CMP = 1;

template <int N>
struct kcov_remote_arg {
	uint32 trace_mode;
	uint32 area_size;
	uint32 num_handles;
	uint32 pad;
	uint64 common_handle;
	uint64 handles[N];
};

#define KCOV_INIT_TRACE32 _IOR('c', 1, uint32)
#define KCOV_INIT_TRACE64 _IOR('c', 1, uint64)
#define KCOV_ENABLE _IO('c', 100)
#define KCOV_DISABLE _IO('c', 101)
#define KCOV_REMOTE_ENABLE _IOW('c', 102, kcov_remote_arg<0>)

#define KCOV_SUBSYSTEM_COMMON (0x00ull << 56)
#define KCOV_SUBSYSTEM_USB (0x01ull << 56)

#define KCOV_SUBSYSTEM_MASK (0xffull << 56)
#define KCOV_INSTANCE_MASK (0xffffffffull)

static bool is_gvisor;

static inline __u64 kcov_remote_handle(__u64 subsys, __u64 inst)
{
	if (subsys & ~KCOV_SUBSYSTEM_MASK || inst & ~KCOV_INSTANCE_MASK)
		return 0;
	return subsys | inst;
}

static bool detect_kernel_bitness();
static bool detect_gvisor();

static void os_init(int argc, char** argv, char* data, size_t data_size)
{
	prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
	is_kernel_64_bit = detect_kernel_bitness();
	is_gvisor = detect_gvisor();
	// Surround the main data mapping with PROT_NONE pages to make virtual address layout more consistent
	// across different configurations (static/non-static build) and C repros.
	// One observed case before: executor had a mapping above the data mapping (output region),
	// while C repros did not have that mapping above, as the result in one case VMA had next link,
	// while in the other it didn't and it caused a bug to not reproduce with the C repro.
	void* got = mmap(data - SYZ_PAGE_SIZE, SYZ_PAGE_SIZE, PROT_NONE, MAP_ANON | MAP_PRIVATE | MAP_FIXED, -1, 0);
	if (data - SYZ_PAGE_SIZE != got)
		failmsg("mmap of left data PROT_NONE page failed", "want %p, got %p", data - SYZ_PAGE_SIZE, got);
	got = mmap(data, data_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANON | MAP_PRIVATE | MAP_FIXED, -1, 0);
	if (data != got)
		failmsg("mmap of data segment failed", "want %p, got %p", data, got);
	got = mmap(data + data_size, SYZ_PAGE_SIZE, PROT_NONE, MAP_ANON | MAP_PRIVATE | MAP_FIXED, -1, 0);
	if (data + data_size != got)
		failmsg("mmap of right data PROT_NONE page failed", "want %p, got %p", data + data_size, got);
}

static intptr_t execute_syscall(const call_t* c, intptr_t a[kMaxArgs])
{
	if (c->call)
		return c->call(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8]);
	return syscall(c->sys_nr, a[0], a[1], a[2], a[3], a[4], a[5]);
}

static void cover_open(cover_t* cov, bool extra)
{
	int fd = open("/sys/kernel/debug/kcov", O_RDWR);
	if (fd == -1)
		fail("open of /sys/kernel/debug/kcov failed");
	if (dup2(fd, cov->fd) < 0)
		failmsg("filed to dup cover fd", "from=%d, to=%d", fd, cov->fd);
	close(fd);
	const int kcov_init_trace = is_kernel_64_bit ? KCOV_INIT_TRACE64 : KCOV_INIT_TRACE32;
	const int cover_size = extra ? kExtraCoverSize : kCoverSize;
	if (ioctl(cov->fd, kcov_init_trace, cover_size))
		fail("cover init trace write failed");
	cov->mmap_alloc_size = cover_size * (is_kernel_64_bit ? 8 : 4);
}

static void cover_protect(cover_t* cov)
{
}

#if SYZ_EXECUTOR_USES_SHMEM
static void cover_unprotect(cover_t* cov)
{
}
#endif

static void cover_mmap(cover_t* cov)
{
	if (cov->data != NULL)
		fail("cover_mmap invoked on an already mmapped cover_t object");
	if (cov->mmap_alloc_size == 0)
		fail("cover_t structure is corrupted");
	// Allocate kcov buffer plus two guard pages surrounding it.
	char* mapped = (char*)mmap(NULL, cov->mmap_alloc_size + 2 * SYZ_PAGE_SIZE,
				   PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
	if (mapped == MAP_FAILED)
		exitf("failed to preallocate kcov buffer");
	// Protect the guard pages.
	int res = mprotect(mapped, SYZ_PAGE_SIZE, PROT_NONE);
	if (res == -1)
		exitf("failed to protect kcov guard page");
	res = mprotect(mapped + SYZ_PAGE_SIZE + cov->mmap_alloc_size,
		       SYZ_PAGE_SIZE, PROT_NONE);
	if (res == -1)
		exitf("failed to protect kcov guard page");
	// Now map the kcov buffer to the file, overwriting the existing mapping above.
	cov->data = (char*)mmap(mapped + SYZ_PAGE_SIZE, cov->mmap_alloc_size,
				PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, cov->fd, 0);
	if (cov->data == MAP_FAILED)
		exitf("cover mmap failed");
	cov->data_end = cov->data + cov->mmap_alloc_size;
	cov->data_offset = is_kernel_64_bit ? sizeof(uint64_t) : sizeof(uint32_t);
	cov->pc_offset = 0;
}

static void cover_enable(cover_t* cov, bool collect_comps, bool extra)
{
	unsigned int kcov_mode = collect_comps ? KCOV_TRACE_CMP : KCOV_TRACE_PC;
	// The KCOV_ENABLE call should be fatal,
	// but in practice ioctl fails with assorted errors (9, 14, 25),
	// so we use exitf.
	if (!extra) {
		if (ioctl(cov->fd, KCOV_ENABLE, kcov_mode))
			exitf("cover enable write trace failed, mode=%d", kcov_mode);
		return;
	}
	kcov_remote_arg<1> arg = {
	    .trace_mode = kcov_mode,
	    // Coverage buffer size of background threads.
	    .area_size = kExtraCoverSize,
	    .num_handles = 1,
	};
	arg.common_handle = kcov_remote_handle(KCOV_SUBSYSTEM_COMMON, procid + 1);
	arg.handles[0] = kcov_remote_handle(KCOV_SUBSYSTEM_USB, procid + 1);
	if (ioctl(cov->fd, KCOV_REMOTE_ENABLE, &arg))
		exitf("remote cover enable write trace failed");
}

static void cover_reset(cover_t* cov)
{
	// Callers in common_linux.h don't check this flag.
	if (!flag_coverage)
		return;
	if (cov == 0) {
		if (current_thread == 0)
			fail("cover_reset: current_thread == 0");
		cov = &current_thread->cov;
	}
	*(uint64*)cov->data = 0;
}

static void cover_collect(cover_t* cov)
{
	if (is_kernel_64_bit)
		cov->size = *(uint64*)cov->data;
	else
		cov->size = *(uint32*)cov->data;
}

#if SYZ_EXECUTOR_USES_SHMEM
static bool use_cover_edges(uint32 pc)
{
	return true;
}

static bool use_cover_edges(uint64 pc)
{
#if defined(__i386__) || defined(__x86_64__)
	if (is_gvisor)
		return false; // gvisor coverage is not a trace, so producing edges won't work
	// Text/modules range for x86_64.
	if (pc < 0xffffffff80000000ull || pc >= 0xffffffffff000000ull) {
		debug("got bad pc: 0x%llx\n", pc);
		doexit(0);
	}
#endif
	return true;
}
#endif

static bool detect_kernel_bitness()
{
	if (sizeof(void*) == 8)
		return true;
	// It turns out to be surprisingly hard to understand if the kernel underneath is 64-bits.
	// A common method is to look at uname.machine. But it is produced in some involved ways,
	// and we will need to know about all strings it returns and in the end it can be overriden
	// during build and lie (and there are known precedents of this).
	// So instead we look at size of addresses in /proc/kallsyms.
	bool wide = true;
	int fd = open("/proc/kallsyms", O_RDONLY);
	if (fd != -1) {
		char buf[16];
		if (read(fd, buf, sizeof(buf)) == sizeof(buf) &&
		    (buf[8] == ' ' || buf[8] == '\t'))
			wide = false;
		close(fd);
	}
	debug("detected %d-bit kernel\n", wide ? 64 : 32);
	return wide;
}

static bool detect_gvisor()
{
	char buf[64] = {};
	// 3 stands for undeclared SYSLOG_ACTION_READ_ALL.
	syscall(__NR_syslog, 3, buf, sizeof(buf) - 1);
	// This is a first line of gvisor dmesg.
	return strstr(buf, "Starting gVisor");
}

// One does not simply exit.
// _exit can in fact fail.
// syzkaller did manage to generate a seccomp filter that prohibits exit_group syscall.
// Previously, we get into infinite recursion via segv_handler in such case
// and corrupted output_data, which does matter in our case since it is shared
// with fuzzer process. Loop infinitely instead. Parent will kill us.
// But one does not simply loop either. Compilers are sure that _exit never returns,
// so they remove all code after _exit as dead. Call _exit via volatile indirection.
// And this does not work as well. _exit has own handling of failing exit_group
// in the form of HLT instruction, it will divert control flow from our loop.
// So call the syscall directly.
NORETURN void doexit(int status)
{
	volatile unsigned i;
	syscall(__NR_exit_group, status);
	for (i = 0;; i++) {
	}
}

// If we need to kill just a single thread (e.g. after cloning), exit_group is not
// the right choice - it will kill all threads, which might eventually lead to
// unnecessary SYZFAIL errors.
NORETURN void doexit_thread(int status)
{
	volatile unsigned i;
	syscall(__NR_exit, status);
	for (i = 0;; i++) {
	}
}

static void setup_nicvf()
{
	// This feature has custom checking precedure rather than just rely on running
	// a simple program with this feature enabled b/c find_vf_interface cannot be made
	// failing. It searches for the nic in init namespace, but then the nic is moved
	// to one of testing namespace, so if number of procs is more than the number of devices,
	// then some of them won't fine a nic (the code is also racy, more than one proc
	// can find the same device and then moving it will fail for all but one).
	// So we have to make find_vf_interface non-failing in case of failures,
	// which means we cannot use it for feature checking.
	if (open("/sys/bus/pci/devices/0000:00:11.0/", O_RDONLY | O_NONBLOCK) == -1)
		fail("PCI device 0000:00:11.0 is not available");
}

static void setup_devlink_pci()
{
	// See comment in setup_nicvf.
	if (open("/sys/bus/pci/devices/0000:00:10.0/", O_RDONLY | O_NONBLOCK) == -1)
		fail("PCI device 0000:00:10.0 is not available");
}

static void setup_delay_kcov()
{
	is_kernel_64_bit = detect_kernel_bitness();
	cover_t cov = {};
	cov.fd = kCoverFd;
	cover_open(&cov, false);
	cover_mmap(&cov);
	cov.data = nullptr;
	cover_mmap(&cov);
	// If delayed kcov mmap is not supported by the kernel,
	// accesses to the second mapping will crash.
	const_cast<volatile char*>(cov.data)[0] = 1;
}

#define SYZ_HAVE_FEATURES 1
static feature_t features[] = {
    {rpc::Feature::DelayKcovMmap, setup_delay_kcov},
    {rpc::Feature::Fault, setup_fault},
    {rpc::Feature::Leak, setup_leak},
    {rpc::Feature::KCSAN, setup_kcsan},
    {rpc::Feature::USBEmulation, setup_usb},
    {rpc::Feature::LRWPANEmulation, setup_802154},
    {rpc::Feature::BinFmtMisc, setup_binfmt_misc},
    {rpc::Feature::Swap, setup_swap},
    {rpc::Feature::NicVF, setup_nicvf},
    {rpc::Feature::DevlinkPCI, setup_devlink_pci},
};
