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

static bool pkeys_enabled;

// The coverage buffer can realistically overflow. In the non-snapshot mode we cannot afford
// very large buffer b/c there are usually multiple procs, and each of them consumes
// significant amount of memory. In snapshot mode we have only one proc, so we can have
// larger coverage buffer.
const int kSnapshotCoverSize = 1024 << 10;

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
#define KCOV_RESET_TRACE _IO('c', 104)

#define KCOV_SUBSYSTEM_COMMON (0x00ull << 56)
#define KCOV_SUBSYSTEM_USB (0x01ull << 56)

#define KCOV_SUBSYSTEM_MASK (0xffull << 56)
#define KCOV_INSTANCE_MASK (0xffffffffull)

static inline __u64 kcov_remote_handle(__u64 subsys, __u64 inst)
{
	if (subsys & ~KCOV_SUBSYSTEM_MASK || inst & ~KCOV_INSTANCE_MASK)
		return 0;
	return subsys | inst;
}

static void os_init(int argc, char** argv, char* data, size_t data_size)
{
	prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
	// Surround the main data mapping with PROT_NONE pages to make virtual address layout more consistent
	// across different configurations (static/non-static build) and C repros.
	// One observed case before: executor had a mapping above the data mapping (output region),
	// while C repros did not have that mapping above, as the result in one case VMA had next link,
	// while in the other it didn't and it caused a bug to not reproduce with the C repro.
	void* got = mmap(data - SYZ_PAGE_SIZE, SYZ_PAGE_SIZE, PROT_NONE, MAP_ANON | MAP_PRIVATE | MAP_FIXED_EXCLUSIVE, -1, 0);
	if (data - SYZ_PAGE_SIZE != got)
		failmsg("mmap of left data PROT_NONE page failed", "want %p, got %p", data - SYZ_PAGE_SIZE, got);
	// NOLINTBEGIN(clang-analyzer-security.MmapWriteExec)
	got = mmap(data, data_size, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_ANON | MAP_PRIVATE | MAP_FIXED_EXCLUSIVE, -1, 0);
	// NOLINTEND(clang-analyzer-security.MmapWriteExec)
	if (data != got)
		failmsg("mmap of data segment failed", "want %p, got %p", data, got);
	got = mmap(data + data_size, SYZ_PAGE_SIZE, PROT_NONE, MAP_ANON | MAP_PRIVATE | MAP_FIXED_EXCLUSIVE, -1, 0);
	if (data + data_size != got)
		failmsg("mmap of right data PROT_NONE page failed", "want %p, got %p", data + data_size, got);

	// A SIGCHLD handler makes sleep in loop exit immediately return with EINTR with a child exits.
	struct sigaction act = {};
	act.sa_handler = [](int) {};
	sigaction(SIGCHLD, &act, nullptr);

	// Use the last available pkey so that C reproducers get the the same keys from pkey_alloc.
	int pkeys[RESERVED_PKEY + 1];
	int npkey = 0;
	for (; npkey <= RESERVED_PKEY; npkey++) {
		int pk = pkey_alloc(0, 0);
		if (pk == -1)
			break;
		if (pk == RESERVED_PKEY) {
			pkeys_enabled = true;
			break;
		}
		pkeys[npkey] = pk;
	}
	while (npkey--)
		pkey_free(pkeys[npkey]);
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
	const int cover_size = extra ? kExtraCoverSize : flag_snapshot ? kSnapshotCoverSize
								       : kCoverSize;
	if (ioctl(cov->fd, kcov_init_trace, cover_size))
		fail("cover init trace write failed");
	cov->data_size = cover_size * (is_kernel_64_bit ? 8 : 4);
	if (pkeys_enabled)
		debug("pkey protection enabled\n");
}

static void cover_close(cover_t* cov)
{
	if (cov->fd == -1)
		fail("attempting to close an invalid cover fd");
	if (cov->enabled) {
		if (ioctl(cov->fd, KCOV_DISABLE, 0))
			fail("KCOV_DISABLE failed");
		cov->enabled = false;
	}
	close(cov->fd);
	cov->fd = -1;
}

static void cover_protect(cover_t* cov)
{
	if (pkeys_enabled && pkey_set(RESERVED_PKEY, PKEY_DISABLE_WRITE))
		debug("pkey_set failed: %d\n", errno);
}

static void cover_unprotect(cover_t* cov)
{
	if (pkeys_enabled && pkey_set(RESERVED_PKEY, 0))
		debug("pkey_set failed: %d\n", errno);
}

static void cover_mmap(cover_t* cov)
{
	if (cov->mmap_alloc_ptr != NULL)
		fail("cover_mmap invoked on an already mmapped cover_t object");
	if (cov->data_size == 0)
		fail("cover_t structure is corrupted");
	// Allocate kcov buffer plus two guard pages surrounding it.
	cov->mmap_alloc_size = cov->data_size + 2 * SYZ_PAGE_SIZE;
	cov->mmap_alloc_ptr = (char*)mmap(NULL, cov->mmap_alloc_size,
					  PROT_NONE, MAP_PRIVATE | MAP_ANON, -1, 0);
	if (cov->mmap_alloc_ptr == MAP_FAILED)
		exitf("failed to preallocate kcov buffer");
	// Now map the kcov buffer to the file, overwriting the existing mapping above.
	int prot = flag_read_only_coverage ? PROT_READ : (PROT_READ | PROT_WRITE);
	void* data_buf = (char*)mmap(cov->mmap_alloc_ptr + SYZ_PAGE_SIZE, cov->data_size,
				     prot, MAP_SHARED | MAP_FIXED, cov->fd, 0);
	if (data_buf == MAP_FAILED)
		exitf("cover mmap failed");
	if (pkeys_enabled && pkey_mprotect(data_buf, cov->data_size, prot, RESERVED_PKEY))
		exitf("failed to pkey_mprotect kcov buffer");
	cov->data = (char*)data_buf;
	cov->data_end = cov->data + cov->data_size;
	cov->data_offset = is_kernel_64_bit ? sizeof(uint64_t) : sizeof(uint32_t);
	cov->pc_offset = 0;
}

static void cover_munmap(cover_t* cov)
{
	if (cov->mmap_alloc_ptr == NULL)
		fail("cover_munmap invoked on a non-mmapped cover_t object");
	if (munmap(cov->mmap_alloc_ptr, cov->mmap_alloc_size))
		fail("cover_munmap failed");
	cov->mmap_alloc_ptr = NULL;
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
		cov->enabled = true;
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
	cov->enabled = true;
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
	if (flag_read_only_coverage) {
		if (ioctl(cov->fd, KCOV_RESET_TRACE, 0))
			fail("KCOV_RESET_TRACE failed");
	} else {
		cover_unprotect(cov);
		*(uint64*)cov->data = 0;
		cover_protect(cov);
	}
	cov->overflow = false;
}

template <typename cover_data_t>
static void cover_collect_impl(cover_t* cov)
{
	cov->size = *(cover_data_t*)cov->data;
	cov->overflow = (cov->data + (cov->size + 2) * sizeof(cover_data_t)) > cov->data_end;
}

static void cover_collect(cover_t* cov)
{
	if (is_kernel_64_bit)
		cover_collect_impl<uint64>(cov);
	else
		cover_collect_impl<uint32>(cov);
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

#define SYZ_HAVE_KCSAN 1
static void setup_kcsan_filter(const std::vector<std::string>& frames)
{
	if (frames.empty())
		return;
	int fd = open("/sys/kernel/debug/kcsan", O_WRONLY);
	if (fd == -1)
		fail("failed to open kcsan debugfs file");
	for (const auto& frame : frames)
		dprintf(fd, "!%s\n", frame.c_str());
	close(fd);
}

static const char* setup_nicvf()
{
	// This feature has custom checking precedure rather than just rely on running
	// a simple program with this feature enabled b/c find_vf_interface cannot be made
	// failing. It searches for the nic in init namespace, but then the nic is moved
	// to one of testing namespace, so if number of procs is more than the number of devices,
	// then some of them won't fine a nic (the code is also racy, more than one proc
	// can find the same device and then moving it will fail for all but one).
	// So we have to make find_vf_interface non-failing in case of failures,
	// which means we cannot use it for feature checking.
	int fd = open("/sys/bus/pci/devices/0000:00:11.0/", O_RDONLY | O_NONBLOCK);
	if (fd == -1)
		return "PCI device 0000:00:11.0 is not available";
	close(fd);
	return NULL;
}

static const char* setup_devlink_pci()
{
	// See comment in setup_nicvf.
	int fd = open("/sys/bus/pci/devices/0000:00:10.0/", O_RDONLY | O_NONBLOCK);
	if (fd == -1)
		return "PCI device 0000:00:10.0 is not available";
	close(fd);
	return NULL;
}

static const char* setup_delay_kcov()
{
	int fd = open("/sys/kernel/debug/kcov", O_RDWR);
	if (fd == -1)
		return "open of /sys/kernel/debug/kcov failed";
	close(fd);
	cover_t cov = {};
	cov.fd = kCoverFd;
	cover_open(&cov, false);
	cover_mmap(&cov);
	char* first = cov.mmap_alloc_ptr;
	cov.mmap_alloc_ptr = nullptr;
	cover_mmap(&cov);
	// If delayed kcov mmap is not supported by the kernel,
	// accesses to the second mapping will crash.
	// Use clock_gettime to check if it's mapped w/o crashing the process.
	const char* error = NULL;
	timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC, &ts)) {
		if (errno != EFAULT)
			fail("clock_gettime failed");
		error = "kernel commit b3d7fe86fbd0 is not present";
	} else {
		munmap(cov.mmap_alloc_ptr, cov.mmap_alloc_size);
	}
	munmap(first, cov.mmap_alloc_size);
	cover_close(&cov);
	return error;
}

static const char* setup_kcov_reset_ioctl()
{
	int fd = open("/sys/kernel/debug/kcov", O_RDWR);
	if (fd == -1)
		return "open of /sys/kernel/debug/kcov failed";
	close(fd);

	cover_t cov = {};
	cov.fd = kCoverFd;
	cover_open(&cov, false);
	cover_mmap(&cov);
	const char* error = NULL;
	cover_enable(&cov, false, false);
	int ret;
	if ((ret = ioctl(cov.fd, KCOV_RESET_TRACE, 0))) {
		if (errno != ENOTTY) {
			fprintf(stderr, "ret: %d, errno: %d\n", ret, errno);
			fail("ioctl(KCOV_RESET_TRACE) failed");
		}
		error = "kernel does not support ioctl(KCOV_RESET_TRACE)";
	}
	cover_munmap(&cov);
	cover_close(&cov);
	return error;
}

static const char* setup_kdump()
{
	if (access("/boot/bzImageKexec", F_OK) != 0)
		return "/boot/bzImageKexec is missing";
	if (access("/usr/sbin/makedumpfile", F_OK) != 0)
		return "/usr/sbin/makedumpfile is missing";
	char cmdline[4096];
	int fd = open("/proc/cmdline", O_RDONLY);
	if (fd < 0)
		return "failed to open /proc/cmdline";
	ssize_t n = read(fd, cmdline, sizeof(cmdline) - 1);
	close(fd);
	if (n <= 0)
		return "failed to read /proc/cmdline";
	cmdline[n] = 0;
	if (strstr(cmdline, "crashkernel=") == NULL)
		return "crashkernel= is not present in /proc/cmdline";

	// Current default values
	char root[128] = "/dev/sda1";
	char console[128] = "ttyS0";
	get_last_opt(cmdline, "root", root, sizeof(root));
	get_last_opt(cmdline, "console", console, sizeof(console));

	char cmd[1024];
	snprintf(cmd, sizeof(cmd),
		 "kexec -p /boot/bzImageKexec --append=\"earlyprintk=serial net.ifnames=0 ima_policy=tcb no_hash_pointers root=%s console=%s vsyscall=native watchdog_thresh=55 irqpoll nr_cpus=1 reset_devices\"",
		 root, console);

	if (system(cmd) != 0)
		return "kexec failed";
	int s_fd = open("/sys/kernel/kexec_crash_loaded", O_RDONLY);
	if (s_fd >= 0) {
		char loaded_status[1];
		ssize_t sn = read(s_fd, loaded_status, sizeof(loaded_status));
		close(s_fd);
		if (sn != 1)
			return "failed to read /sys/kernel/kexec_crash_loaded";
		if (loaded_status[0] != '1')
			return "/sys/kernel/kexec_crash_loaded is not 1";
	}
	return NULL;
}

#define SYZ_HAVE_FEATURES 1
static feature_t features[] = {
    {rpc::Feature::DelayKcovMmap, setup_delay_kcov},
    {rpc::Feature::KcovResetIoctl, setup_kcov_reset_ioctl},
    {rpc::Feature::Fault, setup_fault},
    {rpc::Feature::Leak, setup_leak},
    {rpc::Feature::KCSAN, setup_kcsan},
    {rpc::Feature::USBEmulation, setup_usb},
    {rpc::Feature::LRWPANEmulation, setup_802154},
    {rpc::Feature::BinFmtMisc, setup_binfmt_misc},
    {rpc::Feature::Swap, setup_swap},
    {rpc::Feature::NicVF, setup_nicvf},
    {rpc::Feature::DevlinkPCI, setup_devlink_pci},
    {rpc::Feature::MemoryDump, setup_kdump},
};
