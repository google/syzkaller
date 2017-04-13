// Copyright 2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// This file is shared between executor and csource package.

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>

#include <linux/capability.h>
#include <linux/if.h>
#include <linux/if_tun.h>
#include <linux/kvm.h>
#include <linux/sched.h>
#include <net/if_arp.h>

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

const int kFailStatus = 67;
const int kErrorStatus = 68;
const int kRetryStatus = 69;

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
__attribute__((noreturn)) void doexit(int status)
{
	volatile unsigned i;
	syscall(__NR_exit_group, status);
	for (i = 0;; i++) {
	}
}

#if defined(SYZ_EXECUTOR)
// exit/_exit do not necessary work.
#define exit use_doexit_instead
#define _exit use_doexit_instead
#endif

// logical error (e.g. invalid input program), use as an assert() alernative
__attribute__((noreturn)) void fail(const char* msg, ...)
{
	int e = errno;
	fflush(stdout);
	va_list args;
	va_start(args, msg);
	vfprintf(stderr, msg, args);
	va_end(args);
	fprintf(stderr, " (errno %d)\n", e);
	// ENOMEM/EAGAIN is frequent cause of failures in fuzzing context,
	// so handle it here as non-fatal error.
	doexit((e == ENOMEM || e == EAGAIN) ? kRetryStatus : kFailStatus);
}

#if defined(SYZ_EXECUTOR)
// kernel error (e.g. wrong syscall return value)
__attribute__((noreturn)) void error(const char* msg, ...)
{
	fflush(stdout);
	va_list args;
	va_start(args, msg);
	vfprintf(stderr, msg, args);
	va_end(args);
	fprintf(stderr, "\n");
	doexit(kErrorStatus);
}
#endif

// just exit (e.g. due to temporal ENOMEM error)
__attribute__((noreturn)) void exitf(const char* msg, ...)
{
	int e = errno;
	fflush(stdout);
	va_list args;
	va_start(args, msg);
	vfprintf(stderr, msg, args);
	va_end(args);
	fprintf(stderr, " (errno %d)\n", e);
	doexit(kRetryStatus);
}

static int flag_debug;

void debug(const char* msg, ...)
{
	if (!flag_debug)
		return;
	va_list args;
	va_start(args, msg);
	vfprintf(stdout, msg, args);
	va_end(args);
	fflush(stdout);
}

__thread int skip_segv;
__thread jmp_buf segv_env;

static void segv_handler(int sig, siginfo_t* info, void* uctx)
{
	// Generated programs can contain bad (unmapped/protected) addresses,
	// which cause SIGSEGVs during copyin/copyout.
	// This handler ignores such crashes to allow the program to proceed.
	// We additionally opportunistically check that the faulty address
	// is not within executable data region, because such accesses can corrupt
	// output region and then fuzzer will fail on corrupted data.
	uintptr_t addr = (uintptr_t)info->si_addr;
	const uintptr_t prog_start = 1 << 20;
	const uintptr_t prog_end = 100 << 20;
	if (__atomic_load_n(&skip_segv, __ATOMIC_RELAXED) && (addr < prog_start || addr > prog_end)) {
		debug("SIGSEGV on %p, skipping\n", addr);
		_longjmp(segv_env, 1);
	}
	debug("SIGSEGV on %p, exiting\n", addr);
	doexit(sig);
	for (;;) {
	}
}

static void install_segv_handler()
{
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_sigaction = segv_handler;
	sa.sa_flags = SA_NODEFER | SA_SIGINFO;
	sigaction(SIGSEGV, &sa, NULL);
	sigaction(SIGBUS, &sa, NULL);
}

#define NONFAILING(...)                                              \
	{                                                            \
		__atomic_fetch_add(&skip_segv, 1, __ATOMIC_SEQ_CST); \
		if (_setjmp(segv_env) == 0) {                        \
			__VA_ARGS__;                                 \
		}                                                    \
		__atomic_fetch_sub(&skip_segv, 1, __ATOMIC_SEQ_CST); \
	}

#define BITMASK_LEN(type, bf_len) (type)((1ull << (bf_len)) - 1)

#define BITMASK_LEN_OFF(type, bf_off, bf_len) (type)(BITMASK_LEN(type, (bf_len)) << (bf_off))

#define STORE_BY_BITMASK(type, addr, val, bf_off, bf_len)                         \
	if ((bf_off) == 0 && (bf_len) == 0) {                                     \
		*(type*)(addr) = (type)(val);                                     \
	} else {                                                                  \
		type new_val = *(type*)(addr);                                    \
		new_val &= ~BITMASK_LEN_OFF(type, (bf_off), (bf_len));            \
		new_val |= ((type)(val)&BITMASK_LEN(type, (bf_len))) << (bf_off); \
		*(type*)(addr) = new_val;                                         \
	}

#ifdef __NR_syz_emit_ethernet
static void vsnprintf_check(char* str, size_t size, const char* format, va_list args)
{
	int rv;

	rv = vsnprintf(str, size, format, args);
	if (rv < 0)
		fail("tun: snprintf failed");
	if ((size_t)rv >= size)
		fail("tun: string '%s...' doesn't fit into buffer", str);
}

static void snprintf_check(char* str, size_t size, const char* format, ...)
{
	va_list args;

	va_start(args, format);
	vsnprintf_check(str, size, format, args);
	va_end(args);
}

#define COMMAND_MAX_LEN 128

static void execute_command(const char* format, ...)
{
	va_list args;
	char command[COMMAND_MAX_LEN];
	int rv;

	va_start(args, format);

	vsnprintf_check(command, sizeof(command), format, args);
	rv = system(command);
	if (rv != 0)
		fail("tun: command \"%s\" failed with code %d", &command[0], rv);

	va_end(args);
}

int tunfd = -1;

// sysgen knowns about this constant (maxPids)
#define MAX_PIDS 32
#define ADDR_MAX_LEN 32

#define LOCAL_MAC "aa:aa:aa:aa:aa:%02hx"
#define REMOTE_MAC "bb:bb:bb:bb:bb:%02hx"

#define LOCAL_IPV4 "172.20.%d.170"
#define REMOTE_IPV4 "172.20.%d.187"

#define LOCAL_IPV6 "fd00::%02hxaa"
#define REMOTE_IPV6 "fd00::%02hxbb"

static void initialize_tun(uint64_t pid)
{
	if (pid >= MAX_PIDS)
		fail("tun: no more than %d executors", MAX_PIDS);
	int id = pid;

	tunfd = open("/dev/net/tun", O_RDWR);
	if (tunfd == -1)
		fail("tun: can't open /dev/net/tun");

	char iface[IFNAMSIZ];
	snprintf_check(iface, sizeof(iface), "syz%d", id);

	struct ifreq ifr;
	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, iface, IFNAMSIZ);
	ifr.ifr_flags = IFF_TAP | IFF_NO_PI;
	if (ioctl(tunfd, TUNSETIFF, (void*)&ifr) < 0)
		fail("tun: ioctl(TUNSETIFF) failed");

	char local_mac[ADDR_MAX_LEN];
	snprintf_check(local_mac, sizeof(local_mac), LOCAL_MAC, id);
	char remote_mac[ADDR_MAX_LEN];
	snprintf_check(remote_mac, sizeof(remote_mac), REMOTE_MAC, id);

	char local_ipv4[ADDR_MAX_LEN];
	snprintf_check(local_ipv4, sizeof(local_ipv4), LOCAL_IPV4, id);
	char remote_ipv4[ADDR_MAX_LEN];
	snprintf_check(remote_ipv4, sizeof(remote_ipv4), REMOTE_IPV4, id);

	char local_ipv6[ADDR_MAX_LEN];
	snprintf_check(local_ipv6, sizeof(local_ipv6), LOCAL_IPV6, id);
	char remote_ipv6[ADDR_MAX_LEN];
	snprintf_check(remote_ipv6, sizeof(remote_ipv6), REMOTE_IPV6, id);

	execute_command("ip link set dev %s address %s", iface, local_mac);
	execute_command("ip addr add %s/24 dev %s", local_ipv4, iface);
	execute_command("ip -6 addr add %s/120 dev %s", local_ipv6, iface);
	execute_command("ip neigh add %s lladdr %s dev %s nud permanent", remote_ipv4, remote_mac, iface);
	execute_command("ip -6 neigh add %s lladdr %s dev %s nud permanent", remote_ipv6, remote_mac, iface);
	execute_command("ip link set %s up", iface);
}

static void setup_tun(uint64_t pid, bool enable_tun)
{
	if (enable_tun)
		initialize_tun(pid);
}

static uintptr_t syz_emit_ethernet(uintptr_t a0, uintptr_t a1)
{
	if (tunfd < 0)
		return (uintptr_t)-1;

	int64_t length = a0;
	char* data = (char*)a1;
	return write(tunfd, data, length);
}
#endif // __NR_syz_emit_ethernet

#ifdef __NR_syz_open_dev
static uintptr_t syz_open_dev(uintptr_t a0, uintptr_t a1, uintptr_t a2)
{
	if (a0 == 0xc || a0 == 0xb) {
		// syz_open_dev$char(dev const[0xc], major intptr, minor intptr) fd
		// syz_open_dev$block(dev const[0xb], major intptr, minor intptr) fd
		char buf[128];
		sprintf(buf, "/dev/%s/%d:%d", a0 == 0xc ? "char" : "block", (uint8_t)a1, (uint8_t)a2);
		return open(buf, O_RDWR, 0);
	} else {
		// syz_open_dev(dev strconst, id intptr, flags flags[open_flags]) fd
		char buf[1024];
		char* hash;
		NONFAILING(strncpy(buf, (char*)a0, sizeof(buf)));
		buf[sizeof(buf) - 1] = 0;
		while ((hash = strchr(buf, '#'))) {
			*hash = '0' + (char)(a1 % 10); // 10 devices should be enough for everyone.
			a1 /= 10;
		}
		return open(buf, a2, 0);
	}
}
#endif

#ifdef __NR_syz_open_pts
static uintptr_t syz_open_pts(uintptr_t a0, uintptr_t a1)
{
	// syz_openpts(fd fd[tty], flags flags[open_flags]) fd[tty]
	int ptyno = 0;
	if (ioctl(a0, TIOCGPTN, &ptyno))
		return -1;
	char buf[128];
	sprintf(buf, "/dev/pts/%d", ptyno);
	return open(buf, a1, 0);
}
#endif

#ifdef __NR_syz_fuse_mount
static uintptr_t syz_fuse_mount(uintptr_t a0, uintptr_t a1, uintptr_t a2, uintptr_t a3, uintptr_t a4, uintptr_t a5)
{
	// syz_fuse_mount(target filename, mode flags[fuse_mode], uid uid, gid gid, maxread intptr, flags flags[mount_flags]) fd[fuse]
	uint64_t target = a0;
	uint64_t mode = a1;
	uint64_t uid = a2;
	uint64_t gid = a3;
	uint64_t maxread = a4;
	uint64_t flags = a5;

	int fd = open("/dev/fuse", O_RDWR);
	if (fd == -1)
		return fd;
	char buf[1024];
	sprintf(buf, "fd=%d,user_id=%ld,group_id=%ld,rootmode=0%o", fd, (long)uid, (long)gid, (unsigned)mode & ~3u);
	if (maxread != 0)
		sprintf(buf + strlen(buf), ",max_read=%ld", (long)maxread);
	if (mode & 1)
		strcat(buf, ",default_permissions");
	if (mode & 2)
		strcat(buf, ",allow_other");
	syscall(SYS_mount, "", target, "fuse", flags, buf);
	// Ignore errors, maybe fuzzer can do something useful with fd alone.
	return fd;
}
#endif

#ifdef __NR_syz_fuseblk_mount
static uintptr_t syz_fuseblk_mount(uintptr_t a0, uintptr_t a1, uintptr_t a2, uintptr_t a3, uintptr_t a4, uintptr_t a5, uintptr_t a6, uintptr_t a7)
{
	// syz_fuseblk_mount(target filename, blkdev filename, mode flags[fuse_mode], uid uid, gid gid, maxread intptr, blksize intptr, flags flags[mount_flags]) fd[fuse]
	uint64_t target = a0;
	uint64_t blkdev = a1;
	uint64_t mode = a2;
	uint64_t uid = a3;
	uint64_t gid = a4;
	uint64_t maxread = a5;
	uint64_t blksize = a6;
	uint64_t flags = a7;

	int fd = open("/dev/fuse", O_RDWR);
	if (fd == -1)
		return fd;
	if (syscall(SYS_mknodat, AT_FDCWD, blkdev, S_IFBLK, makedev(7, 199)))
		return fd;
	char buf[256];
	sprintf(buf, "fd=%d,user_id=%ld,group_id=%ld,rootmode=0%o", fd, (long)uid, (long)gid, (unsigned)mode & ~3u);
	if (maxread != 0)
		sprintf(buf + strlen(buf), ",max_read=%ld", (long)maxread);
	if (blksize != 0)
		sprintf(buf + strlen(buf), ",blksize=%ld", (long)blksize);
	if (mode & 1)
		strcat(buf, ",default_permissions");
	if (mode & 2)
		strcat(buf, ",allow_other");
	syscall(SYS_mount, blkdev, target, "fuseblk", flags, buf);
	// Ignore errors, maybe fuzzer can do something useful with fd alone.
	return fd;
}
#endif

#ifdef __NR_syz_kvm_setup_cpu
#if defined(__x86_64__)
#include "common_kvm_amd64.h"
#elif defined(__aarch64__)
#include "common_kvm_arm64.h"
#else
static uintptr_t syz_kvm_setup_cpu(uintptr_t a0, uintptr_t a1, uintptr_t a2, uintptr_t a3, uintptr_t a4, uintptr_t a5, uintptr_t a6, uintptr_t a7)
{
	return 0;
}
#endif
#endif // #ifdef __NR_syz_kvm_setup_cpu

static uintptr_t execute_syscall(int nr, uintptr_t a0, uintptr_t a1, uintptr_t a2, uintptr_t a3, uintptr_t a4, uintptr_t a5, uintptr_t a6, uintptr_t a7, uintptr_t a8)
{
	switch (nr) {
	default:
		return syscall(nr, a0, a1, a2, a3, a4, a5);
#ifdef __NR_syz_test
	case __NR_syz_test:
		return 0;
#endif
#ifdef __NR_syz_open_dev
	case __NR_syz_open_dev:
		return syz_open_dev(a0, a1, a2);
#endif
#ifdef __NR_syz_open_pts
	case __NR_syz_open_pts:
		return syz_open_pts(a0, a1);
#endif
#ifdef __NR_syz_fuse_mount
	case __NR_syz_fuse_mount:
		return syz_fuse_mount(a0, a1, a2, a3, a4, a5);
#endif
#ifdef __NR_syz_fuseblk_mount
	case __NR_syz_fuseblk_mount:
		return syz_fuseblk_mount(a0, a1, a2, a3, a4, a5, a6, a7);
#endif
#ifdef __NR_syz_emit_ethernet
	case __NR_syz_emit_ethernet:
		return syz_emit_ethernet(a0, a1);
#endif
#ifdef __NR_syz_kvm_setup_cpu
	case __NR_syz_kvm_setup_cpu:
		return syz_kvm_setup_cpu(a0, a1, a2, a3, a4, a5, a6, a7);
#endif
	}
}

static void setup_main_process()
{
	// Don't need that SIGCANCEL/SIGSETXID glibc stuff.
	// SIGCANCEL sent to main thread causes it to exit
	// without bringing down the whole group.
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = SIG_IGN;
	syscall(SYS_rt_sigaction, 0x20, &sa, NULL, 8);
	syscall(SYS_rt_sigaction, 0x21, &sa, NULL, 8);
	install_segv_handler();

	char tmpdir_template[] = "./syzkaller.XXXXXX";
	char* tmpdir = mkdtemp(tmpdir_template);
	if (!tmpdir)
		fail("failed to mkdtemp");
	if (chmod(tmpdir, 0777))
		fail("failed to chmod");
	if (chdir(tmpdir))
		fail("failed to chdir");
}

static void loop();

static void sandbox_common()
{
	prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
	setpgrp();
	setsid();

	struct rlimit rlim;
	rlim.rlim_cur = rlim.rlim_max = 128 << 20;
	setrlimit(RLIMIT_AS, &rlim);
	rlim.rlim_cur = rlim.rlim_max = 1 << 20;
	setrlimit(RLIMIT_FSIZE, &rlim);
	rlim.rlim_cur = rlim.rlim_max = 1 << 20;
	setrlimit(RLIMIT_STACK, &rlim);
	rlim.rlim_cur = rlim.rlim_max = 0;
	setrlimit(RLIMIT_CORE, &rlim);

	// CLONE_NEWIPC/CLONE_IO cause EINVAL on some systems, so we do them separately of clone.
	unshare(CLONE_NEWNS);
	unshare(CLONE_NEWIPC);
	unshare(CLONE_IO);
}

#if defined(SYZ_EXECUTOR) || defined(SYZ_SANDBOX_NONE)
static int do_sandbox_none(int executor_pid, bool enable_tun)
{
	int pid = fork();
	if (pid)
		return pid;

	sandbox_common();
#ifdef __NR_syz_emit_ethernet
	setup_tun(executor_pid, enable_tun);
#endif

	loop();
	doexit(1);
}
#endif

#if defined(SYZ_EXECUTOR) || defined(SYZ_SANDBOX_SETUID)
static int do_sandbox_setuid(int executor_pid, bool enable_tun)
{
	int pid = fork();
	if (pid)
		return pid;

	sandbox_common();
#ifdef __NR_syz_emit_ethernet
	setup_tun(executor_pid, enable_tun);
#endif

	const int nobody = 65534;
	if (setgroups(0, NULL))
		fail("failed to setgroups");
	if (syscall(SYS_setresgid, nobody, nobody, nobody))
		fail("failed to setresgid");
	if (syscall(SYS_setresuid, nobody, nobody, nobody))
		fail("failed to setresuid");

	loop();
	doexit(1);
}
#endif

#if defined(SYZ_EXECUTOR) || defined(SYZ_SANDBOX_NAMESPACE)
static int real_uid;
static int real_gid;
static int epid;
static bool etun;
__attribute__((aligned(64 << 10))) static char sandbox_stack[1 << 20];

static bool write_file(const char* file, const char* what, ...)
{
	char buf[1024];
	va_list args;
	va_start(args, what);
	vsnprintf(buf, sizeof(buf), what, args);
	va_end(args);
	buf[sizeof(buf) - 1] = 0;
	int len = strlen(buf);

	int fd = open(file, O_WRONLY | O_CLOEXEC);
	if (fd == -1)
		return false;
	if (write(fd, buf, len) != len) {
		close(fd);
		return false;
	}
	close(fd);
	return true;
}

static int namespace_sandbox_proc(void* arg)
{
	sandbox_common();

	// /proc/self/setgroups is not present on some systems, ignore error.
	write_file("/proc/self/setgroups", "deny");
	if (!write_file("/proc/self/uid_map", "0 %d 1\n", real_uid))
		fail("write of /proc/self/uid_map failed");
	if (!write_file("/proc/self/gid_map", "0 %d 1\n", real_gid))
		fail("write of /proc/self/gid_map failed");

#ifdef __NR_syz_emit_ethernet
	// For sandbox namespace we setup tun after initializing uid mapping,
	// otherwise ip commands fail.
	setup_tun(epid, etun);
#endif

	if (mkdir("./syz-tmp", 0777))
		fail("mkdir(syz-tmp) failed");
	if (mount("", "./syz-tmp", "tmpfs", 0, NULL))
		fail("mount(tmpfs) failed");
	if (mkdir("./syz-tmp/newroot", 0777))
		fail("mkdir failed");
	if (mkdir("./syz-tmp/newroot/dev", 0700))
		fail("mkdir failed");
	if (mount("/dev", "./syz-tmp/newroot/dev", NULL, MS_BIND | MS_REC | MS_PRIVATE, NULL))
		fail("mount(dev) failed");
	if (mkdir("./syz-tmp/pivot", 0777))
		fail("mkdir failed");
	if (syscall(SYS_pivot_root, "./syz-tmp", "./syz-tmp/pivot")) {
		debug("pivot_root failed");
		if (chdir("./syz-tmp"))
			fail("chdir failed");
	} else {
		if (chdir("/"))
			fail("chdir failed");
		if (umount2("./pivot", MNT_DETACH))
			fail("umount failed");
	}
	if (chroot("./newroot"))
		fail("chroot failed");
	if (chdir("/"))
		fail("chdir failed");

	// Drop CAP_SYS_PTRACE so that test processes can't attach to parent processes.
	// Previously it lead to hangs because the loop process stopped due to SIGSTOP.
	// Note that a process can always ptrace its direct children, which is enough
	// for testing purposes.
	struct __user_cap_header_struct cap_hdr = {};
	struct __user_cap_data_struct cap_data[2] = {};
	cap_hdr.version = _LINUX_CAPABILITY_VERSION_3;
	cap_hdr.pid = getpid();
	if (syscall(SYS_capget, &cap_hdr, &cap_data))
		fail("capget failed");
	cap_data[0].effective &= ~(1 << CAP_SYS_PTRACE);
	cap_data[0].permitted &= ~(1 << CAP_SYS_PTRACE);
	cap_data[0].inheritable &= ~(1 << CAP_SYS_PTRACE);
	if (syscall(SYS_capset, &cap_hdr, &cap_data))
		fail("capset failed");

	loop();
	doexit(1);
}

static int do_sandbox_namespace(int executor_pid, bool enable_tun)
{
	real_uid = getuid();
	real_gid = getgid();
	epid = executor_pid;
	etun = enable_tun;
	mprotect(sandbox_stack, 4096, PROT_NONE); // to catch stack underflows
	return clone(namespace_sandbox_proc, &sandbox_stack[sizeof(sandbox_stack) - 64],
		     CLONE_NEWUSER | CLONE_NEWPID | CLONE_NEWUTS | CLONE_NEWNET, NULL);
}
#endif

#if defined(SYZ_EXECUTOR) || defined(SYZ_REPEAT)
// One does not simply remove a directory.
// There can be mounts, so we need to try to umount.
// Moreover, a mount can be mounted several times, so we need to try to umount in a loop.
// Moreover, after umount a dir can become non-empty again, so we need another loop.
// Moreover, a mount can be re-mounted as read-only and then we will fail to make a dir empty.
static void remove_dir(const char* dir)
{
	DIR* dp;
	struct dirent* ep;
	int iter = 0;
retry:
	dp = opendir(dir);
	if (dp == NULL) {
		if (errno == EMFILE) {
			// This happens when the test process casts prlimit(NOFILE) on us.
			// Ideally we somehow prevent test processes from messing with parent processes.
			// But full sandboxing is expensive, so let's ignore this error for now.
			exitf("opendir(%s) failed due to NOFILE, exiting");
		}
		exitf("opendir(%s) failed", dir);
	}
	while ((ep = readdir(dp))) {
		if (strcmp(ep->d_name, ".") == 0 || strcmp(ep->d_name, "..") == 0)
			continue;
		char filename[FILENAME_MAX];
		snprintf(filename, sizeof(filename), "%s/%s", dir, ep->d_name);
		struct stat st;
		if (lstat(filename, &st))
			exitf("lstat(%s) failed", filename);
		if (S_ISDIR(st.st_mode)) {
			remove_dir(filename);
			continue;
		}
		int i;
		for (i = 0;; i++) {
			debug("unlink(%s)\n", filename);
			if (unlink(filename) == 0)
				break;
			if (errno == EROFS) {
				debug("ignoring EROFS\n");
				break;
			}
			if (errno != EBUSY || i > 100)
				exitf("unlink(%s) failed", filename);
			debug("umount(%s)\n", filename);
			if (umount2(filename, MNT_DETACH))
				exitf("umount(%s) failed", filename);
		}
	}
	closedir(dp);
	int i;
	for (i = 0;; i++) {
		debug("rmdir(%s)\n", dir);
		if (rmdir(dir) == 0)
			break;
		if (i < 100) {
			if (errno == EROFS) {
				debug("ignoring EROFS\n");
				break;
			}
			if (errno == EBUSY) {
				debug("umount(%s)\n", dir);
				if (umount2(dir, MNT_DETACH))
					exitf("umount(%s) failed", dir);
				continue;
			}
			if (errno == ENOTEMPTY) {
				if (iter < 100) {
					iter++;
					goto retry;
				}
			}
		}
		exitf("rmdir(%s) failed", dir);
	}
}
#endif

#if defined(SYZ_EXECUTOR) || defined(SYZ_REPEAT)
static uint64_t current_time_ms()
{
	struct timespec ts;

	if (clock_gettime(CLOCK_MONOTONIC, &ts))
		fail("clock_gettime failed");
	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}
#endif

#if defined(SYZ_REPEAT)
static void test();

void loop()
{
	int iter;
	for (iter = 0;; iter++) {
		char cwdbuf[256];
		sprintf(cwdbuf, "./%d", iter);
		if (mkdir(cwdbuf, 0777))
			fail("failed to mkdir");
		int pid = fork();
		if (pid < 0)
			fail("clone failed");
		if (pid == 0) {
			prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
			setpgrp();
			if (chdir(cwdbuf))
				fail("failed to chdir");
			test();
			doexit(0);
		}
		int status = 0;
		uint64_t start = current_time_ms();
		for (;;) {
			int res = waitpid(-1, &status, __WALL | WNOHANG);
			if (res == pid)
				break;
			usleep(1000);
			if (current_time_ms() - start > 5 * 1000) {
				kill(-pid, SIGKILL);
				kill(pid, SIGKILL);
				while (waitpid(-1, &status, __WALL) != pid) {
				}
				break;
			}
		}
		remove_dir(cwdbuf);
	}
}
#endif
