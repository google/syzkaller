// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#include <algorithm>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <linux/futex.h>
#include <linux/reboot.h>
#include <pthread.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/prctl.h>
#include <sys/reboot.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "syscalls.h"

#define KCOV_INIT_TRACE _IOR('c', 1, unsigned long)
#define KCOV_INIT_TABLE _IOR('c', 2, unsigned long)
#define KCOV_ENABLE _IO('c', 100)
#define KCOV_DISABLE _IO('c', 101)

const int kInFd = 3;
const int kOutFd = 4;
const int kInPipeFd = 5;
const int kOutPipeFd = 6;
const int kMaxInput = 2 << 20;
const int kMaxOutput = 16 << 20;
const int kMaxArgs = 9;
const int kMaxThreads = 16;
const int kMaxCommands = 4 << 10;
const int kCoverSize = 16 << 10;

const uint64_t instr_eof = -1;
const uint64_t instr_copyin = -2;
const uint64_t instr_copyout = -3;

const uint64_t arg_const = 0;
const uint64_t arg_result = 1;
const uint64_t arg_data = 2;

const int kFailStatus = 67;
const int kErrorStatus = 68;

// We use the default value instead of results of failed syscalls.
// -1 is an invalid fd and an invalid address and deterministic,
// so good enough for our purposes.
const uint64_t default_value = -1;

bool flag_debug;
bool flag_cover;
bool flag_threaded;
bool flag_collide;
bool flag_deduplicate;
bool flag_drop_privs;

__attribute__((aligned(64 << 10))) char input_data[kMaxInput];
__attribute__((aligned(64 << 10))) char output_data[kMaxOutput];
uint32_t* output_pos;
int completed;
int running;
bool collide;
int real_uid;
int real_gid;

struct res_t {
	bool executed;
	uint64_t val;
};

res_t results[kMaxCommands];

struct thread_t {
	bool created;
	int id;
	pthread_t th;
	uintptr_t* cover_data;
	uint64_t* copyout_pos;
	int ready;
	int done;
	bool handled;
	int call_n;
	int call_index;
	int call_num;
	int num_args;
	uint64_t args[kMaxArgs];
	uint64_t res;
	uint64_t reserrno;
	uintptr_t cover_size;
	int cover_fd;
};

thread_t threads[kMaxThreads];
char sandbox_stack[1 << 20];

__attribute__((noreturn)) void fail(const char* msg, ...);
__attribute__((noreturn)) void error(const char* msg, ...);
__attribute__((noreturn)) void exitf(const char* msg, ...);
void debug(const char* msg, ...);
int sandbox(void* arg);
void loop();
void execute_one();
uint64_t read_input(uint64_t** input_posp, bool peek = false);
uint64_t read_arg(uint64_t** input_posp);
uint64_t read_result(uint64_t** input_posp);
void write_output(uint32_t v);
void copyin(char* addr, uint64_t val, uint64_t size);
uint64_t copyout(char* addr, uint64_t size);
thread_t* schedule_call(int n, int call_index, int call_num, uint64_t num_args, uint64_t* args, uint64_t* pos);
void execute_call(thread_t* th);
void handle_completion(thread_t* th);
void thread_create(thread_t* th, int id);
void* worker_thread(void* arg);
bool write_file(const char* file, const char* what, ...);
void remove_dir(const char* dir);
uint64_t current_time_ms();
void cover_open();
void cover_enable(thread_t* th);
void cover_reset(thread_t* th);
uintptr_t cover_read(thread_t* th);
uintptr_t cover_dedup(thread_t* th, uintptr_t n);

int main(int argc, char** argv)
{
	if (argc == 2 && strcmp(argv[1], "reboot") == 0) {
		reboot(LINUX_REBOOT_CMD_RESTART);
		return 0;
	}

	prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
	if (mmap(&input_data[0], kMaxInput, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED, kInFd, 0) != &input_data[0])
		fail("mmap of input file failed");
	if (mmap(&output_data[0], kMaxOutput, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, kOutFd, 0) != &output_data[0])
		fail("mmap of output file failed");
	// Prevent random programs to mess with these fds.
	// Due to races in collider mode, a program can e.g. ftruncate one of these fds,
	// which will cause fuzzer to crash.
	// That's also the reason why we close kInPipeFd/kOutPipeFd below.
	close(kInFd);
	close(kOutFd);

	uint64_t flags = *(uint64_t*)input_data;
	flag_debug = flags & (1 << 0);
	flag_cover = flags & (1 << 1);
	flag_threaded = flags & (1 << 2);
	flag_collide = flags & (1 << 3);
	flag_deduplicate = flags & (1 << 4);
	flag_drop_privs = flags & (1 << 5);
	if (!flag_threaded)
		flag_collide = false;

	cover_open();

	// Don't need that SIGCANCEL/SIGSETXID glibc stuff.
	// SIGCANCEL sent to main thread causes it to exit
	// without bringing down the whole group.
	struct sigaction sa;
	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = SIG_IGN;
	syscall(SYS_rt_sigaction, 0x20, &sa, NULL, 8);
	syscall(SYS_rt_sigaction, 0x21, &sa, NULL, 8);

	int pid = -1;
	if (flag_drop_privs) {
		real_uid = getuid();
		real_gid = getgid();
		pid = clone(sandbox, &sandbox_stack[sizeof(sandbox_stack) - 8],
			    CLONE_NEWUSER | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWUTS | CLONE_NEWNET, NULL);
	} else {
		pid = fork();
		if (pid == 0) {
			loop();
			exit(1);
		}
	}
	if (pid < 0)
		fail("clone failed");
	debug("spawned loop pid %d\n", pid);
	int status = 0;
	while (waitpid(pid, &status, __WALL) != pid) {
	}
	status = WEXITSTATUS(status);
	if (status == kFailStatus)
		fail("loop failed");
	if (status == kErrorStatus)
		error("loop errored");
	fail("loop exited with status %d", status);
	return 0;
}

void loop()
{
	for (int iter = 0;; iter++) {
		// Create a new private work dir for this test (removed at the end of the loop).
		char cwdbuf[256];
		sprintf(cwdbuf, "./%d", iter);
		if (mkdir(cwdbuf, 0777))
			fail("failed to mkdir");

		char tmp;
		if (read(kInPipeFd, &tmp, 1) != 1)
			fail("control pipe read failed");

		int pid = fork();
		if (pid < 0)
			fail("clone failed");
		if (pid == 0) {
			prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
			setpgrp();
			if (chdir(cwdbuf))
				fail("failed to chdir");
			close(kInPipeFd);
			close(kOutPipeFd);
			execute_one();
			debug("worker exiting\n");
			exit(0);
		}
		debug("spawned worker pid %d\n", pid);

		// We used to use sigtimedwait(SIGCHLD) to wait for the subprocess.
		// But SIGCHLD is also delivered when a process stops/continues,
		// so it would require a loop with status analysis and timeout recalculation.
		// SIGCHLD should also unblock the usleep below, so the spin loop
		// should be as efficient as sigtimedwait.
		int status = 0;
		uint64_t start = current_time_ms();
		for (;;) {
			int res = waitpid(pid, &status, __WALL | WNOHANG);
			int errno0 = errno;
			if (res == pid) {
				debug("waitpid(%d)=%d (%d)\n", pid, res, errno0);
				break;
			}
			usleep(1000);
			if (current_time_ms() - start > 5 * 1000) {
				debug("waitpid(%d)=%d (%d)\n", pid, res, errno0);
				debug("killing\n");
				kill(-pid, SIGKILL);
				kill(pid, SIGKILL);
				int res = waitpid(pid, &status, __WALL);
				debug("waitpid(%d)=%d (%d)\n", pid, res, errno);
				if (res != pid)
					fail("waitpid failed");
				break;
			}
		}
		status = WEXITSTATUS(status);
		if (status == kFailStatus)
			fail("child failed");
		if (status == kErrorStatus)
			error("child errored");
		remove_dir(cwdbuf);
		if (write(kOutPipeFd, &tmp, 1) != 1)
			fail("control pipe write failed");
	}
}

int sandbox(void* arg)
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
	unshare(CLONE_NEWIPC);
	unshare(CLONE_IO);

	// /proc/self/setgroups is not present on some systems, ignore error.
	write_file("/proc/self/setgroups", "deny");
	if (!write_file("/proc/self/uid_map", "0 %d 1\n", real_uid))
		fail("write of /proc/self/uid_map failed");
	if (!write_file("/proc/self/gid_map", "0 %d 1\n", real_gid))
		fail("write of /proc/self/gid_map failed");

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
		debug("pivot_root failed\n");
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

	loop();
	exit(1);
}

void execute_one()
{
retry:
	uint64_t* input_pos = (uint64_t*)&input_data[0];
	read_input(&input_pos); // flags
	output_pos = (uint32_t*)&output_data[0];
	write_output(0); // Number of executed syscalls (updated later).

	if (!collide && !flag_threaded)
		cover_enable(&threads[0]);

	int call_index = 0;
	for (int n = 0;; n++) {
		uint64_t call_num = read_input(&input_pos);
		if (call_num == instr_eof)
			break;
		if (call_num == instr_copyin) {
			char* addr = (char*)read_input(&input_pos);
			uint64_t typ = read_input(&input_pos);
			uint64_t size = read_input(&input_pos);
			debug("copyin to %p\n", addr);
			switch (typ) {
			case arg_const: {
				uint64_t arg = read_input(&input_pos);
				copyin(addr, arg, size);
				break;
			}
			case arg_result: {
				uint64_t val = read_result(&input_pos);
				copyin(addr, val, size);
				break;
			}
			case arg_data: {
				memcpy(addr, input_pos, size);
				// Read out the data.
				for (uint64_t i = 0; i < (size + 7) / 8; i++)
					read_input(&input_pos);
				break;
			}
			default:
				fail("bad argument type %lu", typ);
			}
			continue;
		}
		if (call_num == instr_copyout) {
			read_input(&input_pos); // addr
			read_input(&input_pos); // size
			// The copyout will happen when/if the call completes.
			continue;
		}

		// Normal syscall.
		if (call_num >= sizeof(syscalls) / sizeof(syscalls[0]))
			fail("invalid command number %lu", call_num);
		uint64_t num_args = read_input(&input_pos);
		if (num_args > kMaxArgs)
			fail("command has bad number of arguments %lu", num_args);
		uint64_t args[kMaxArgs] = {};
		for (uint64_t i = 0; i < num_args; i++)
			args[i] = read_arg(&input_pos);
		for (uint64_t i = num_args; i < 6; i++)
			args[i] = 0;
		thread_t* th = schedule_call(n, call_index++, call_num, num_args, args, input_pos);

		if (collide && (call_index % 2) == 0) {
			// Don't wait for every other call.
			// We already have results from the previous execution.
		} else if (flag_threaded) {
			// Wait for call completion.
			uint64_t start = current_time_ms();
			uint64_t now = start;
			for (;;) {
				timespec ts = {};
				ts.tv_sec = 0;
				ts.tv_nsec = (100 - (now - start)) * 1000 * 1000;
				syscall(SYS_futex, &th->done, FUTEX_WAIT, 0, &ts);
				if (__atomic_load_n(&th->done, __ATOMIC_RELAXED))
					break;
				now = current_time_ms();
				if (now - start > 100)
					break;
			}
			if (__atomic_load_n(&th->done, __ATOMIC_ACQUIRE))
				handle_completion(th);
			// Check if any of previous calls have completed.
			// Give them some additional time, because they could have been
			// just unblocked by the current call.
			if (running < 0)
				fail("running = %d", running);
			if (running > 0) {
				bool last = read_input(&input_pos, true) == instr_eof;
				usleep(last ? 1000 : 100);
				for (int i = 0; i < kMaxThreads; i++) {
					th = &threads[i];
					if (__atomic_load_n(&th->done, __ATOMIC_ACQUIRE) && !th->handled)
						handle_completion(th);
				}
			}
		} else {
			// Execute directly.
			if (th != &threads[0])
				fail("using non-main thread in non-thread mode");
			execute_call(th);
			handle_completion(th);
		}
	}

	if (flag_collide && !collide) {
		debug("enabling collider\n");
		collide = true;
		goto retry;
	}
}

thread_t* schedule_call(int n, int call_index, int call_num, uint64_t num_args, uint64_t* args, uint64_t* pos)
{
	// Find a spare thread to execute the call.
	int i;
	for (i = 0; i < kMaxThreads; i++) {
		thread_t* th = &threads[i];
		if (!th->created)
			thread_create(th, i);
		if (__atomic_load_n(&th->done, __ATOMIC_ACQUIRE)) {
			if (!th->handled)
				handle_completion(th);
			break;
		}
	}
	if (i == kMaxThreads)
		exitf("out of threads");
	thread_t* th = &threads[i];
	debug("scheduling call %d [%s] on thread %d\n", call_index, syscalls[call_num].name, th->id);
	if (th->ready || !th->done || !th->handled)
		fail("bad thread state in schedule: ready=%d done=%d handled=%d", th->ready, th->done, th->handled);
	th->copyout_pos = pos;
	th->done = false;
	th->handled = false;
	th->call_n = n;
	th->call_index = call_index;
	th->call_num = call_num;
	th->num_args = num_args;
	for (int i = 0; i < kMaxArgs; i++)
		th->args[i] = args[i];
	__atomic_store_n(&th->ready, 1, __ATOMIC_RELEASE);
	syscall(SYS_futex, &th->ready, FUTEX_WAKE);
	running++;
	return th;
}

void handle_completion(thread_t* th)
{
	debug("completion of call %d [%s] on thread %d\n", th->call_index, syscalls[th->call_num].name, th->id);
	if (th->ready || !th->done || th->handled)
		fail("bad thread state in completion: ready=%d done=%d handled=%d",
		     th->ready, th->done, th->handled);
	if (th->res != (uint64_t)-1) {
		results[th->call_n].executed = true;
		results[th->call_n].val = th->res;
		for (bool done = false; !done;) {
			th->call_n++;
			uint64_t call_num = read_input(&th->copyout_pos);
			switch (call_num) {
			case instr_copyout: {
				char* addr = (char*)read_input(&th->copyout_pos);
				uint64_t size = read_input(&th->copyout_pos);
				uint64_t val = copyout(addr, size);
				results[th->call_n].executed = true;
				results[th->call_n].val = val;
				debug("copyout from %p\n", addr);
				break;
			}
			default:
				done = true;
				break;
			}
		}
	}
	if (!collide) {
		write_output(th->call_index);
		write_output(th->call_num);
		write_output(th->res != (uint64_t)-1 ? 0 : th->reserrno);
		write_output(th->cover_size);
		// Truncate PCs to uint32_t assuming that they fit into 32-bits.
		// True for x86_64 and arm64 without KASLR.
		for (uint32_t i = 0; i < th->cover_size; i++)
			write_output((uint32_t)th->cover_data[i + 1]);
		completed++;
		__atomic_store_n((uint32_t*)&output_data[0], completed, __ATOMIC_RELEASE);
	}
	th->handled = true;
	running--;
}

void thread_create(thread_t* th, int id)
{
	th->created = true;
	th->id = id;
	th->done = true;
	th->handled = true;
	if (flag_threaded) {
		pthread_attr_t attr;
		pthread_attr_init(&attr);
		pthread_attr_setstacksize(&attr, 128 << 10);
		if (pthread_create(&th->th, &attr, worker_thread, th))
			exitf("pthread_create failed");
		pthread_attr_destroy(&attr);
	}
}

void* worker_thread(void* arg)
{
	thread_t* th = (thread_t*)arg;

	cover_enable(th);
	for (;;) {
		while (!__atomic_load_n(&th->ready, __ATOMIC_ACQUIRE))
			syscall(SYS_futex, &th->ready, FUTEX_WAIT, 0, 0);
		execute_call(th);
	}
	return 0;
}

void execute_call(thread_t* th)
{
	th->ready = false;
	call_t* call = &syscalls[th->call_num];
	debug("#%d: %s(", th->id, call->name);
	for (int i = 0; i < th->num_args; i++) {
		if (i != 0)
			debug(", ");
		debug("0x%lx", th->args[i]);
	}
	debug(")\n");

	cover_reset(th);
	switch (call->sys_nr) {
	default: {
		if (th->num_args > 6)
			fail("bad number of arguments");
		th->res = syscall(call->sys_nr, th->args[0], th->args[1], th->args[2], th->args[3], th->args[4], th->args[5]);
		break;
	}
	case __NR_syz_open_dev: {
		// syz_open_dev(dev strconst, id intptr, flags flags[open_flags]) fd
		const char* dev = (char*)th->args[0];
		uint64_t id = th->args[1];
		uint64_t flags = th->args[2];
		char buf[128];
		strncpy(buf, dev, sizeof(buf));
		buf[sizeof(buf) - 1] = 0;
		char* hash = strchr(buf, '#');
		if (hash != NULL)
			*hash = '0' + (char)(id % 10); // 10 devices should be enough for everyone.
		debug("syz_open_dev(\"%s\", 0x%lx, 0)\n", buf, flags);
		th->res = open(buf, flags, 0);
		break;
	}
	case __NR_syz_open_pts: {
		// syz_openpts(fd fd[tty], flags flags[open_flags]) fd[tty]
		int ptyno = 0;
		if (ioctl(th->args[0], TIOCGPTN, &ptyno) == 0) {
			char buf[128];
			sprintf(buf, "/dev/pts/%d", ptyno);
			th->res = open(buf, th->args[1], 0);
		} else {
			th->res = -1;
		}
		break;
	}
	case __NR_syz_fuse_mount: {
		// syz_fuse_mount(target filename, mode flags[fuse_mode], uid uid, gid gid, maxread intptr, flags flags[mount_flags]) fd[fuse]
		uint64_t target = th->args[0];
		uint64_t mode = th->args[1];
		uint64_t uid = th->args[2];
		uint64_t gid = th->args[3];
		uint64_t maxread = th->args[4];
		uint64_t flags = th->args[5];

		int fd = open("/dev/fuse", O_RDWR);
		if (fd != -1) {
			char buf[256];
			sprintf(buf, "fd=%d,user_id=%lu,group_id=%lu,rootmode=0%o", fd, uid, gid, (unsigned)mode & ~3u);
			if (maxread != 0)
				sprintf(buf + strlen(buf), ",max_read=%lu", maxread);
			if (mode & 1)
				strcat(buf, ",default_permissions");
			if (mode & 2)
				strcat(buf, ",allow_other");
			syscall(SYS_mount, "", target, "fuse", flags, buf);
			// Ignore errors, maybe fuzzer can do something useful with fd alone.
		}
		th->res = fd;
		break;
	}
	case __NR_syz_fuseblk_mount: {
		// syz_fuseblk_mount(target filename, blkdev filename, mode flags[fuse_mode], uid uid, gid gid, maxread intptr, blksize intptr, flags flags[mount_flags]) fd[fuse]
		uint64_t target = th->args[0];
		uint64_t blkdev = th->args[1];
		uint64_t mode = th->args[2];
		uint64_t uid = th->args[3];
		uint64_t gid = th->args[4];
		uint64_t maxread = th->args[5];
		uint64_t blksize = th->args[6];
		uint64_t flags = th->args[7];

		int fd = open("/dev/fuse", O_RDWR);
		if (fd != -1) {
			if (syscall(SYS_mknodat, AT_FDCWD, blkdev, S_IFBLK, makedev(7, 199)) == 0) {
				char buf[256];
				sprintf(buf, "fd=%d,user_id=%lu,group_id=%lu,rootmode=0%o", fd, uid, gid, (unsigned)mode & ~3u);
				if (maxread != 0)
					sprintf(buf + strlen(buf), ",max_read=%lu", maxread);
				if (blksize != 0)
					sprintf(buf + strlen(buf), ",blksize=%lu", blksize);
				if (mode & 1)
					strcat(buf, ",default_permissions");
				if (mode & 2)
					strcat(buf, ",allow_other");
				syscall(SYS_mount, blkdev, target, "fuseblk", flags, buf);
				// Ignore errors, maybe fuzzer can do something useful with fd alone.
			}
		}
		th->res = fd;
		break;
	}
	}
	th->reserrno = errno;
	th->cover_size = cover_read(th);

	if (th->res == (uint64_t)-1)
		debug("#%d: %s = errno(%d)\n", th->id, call->name, th->reserrno);
	else
		debug("#%d: %s = 0x%lx\n", th->id, call->name, th->res);
	__atomic_store_n(&th->done, 1, __ATOMIC_RELEASE);
	syscall(SYS_futex, &th->done, FUTEX_WAKE);
}

void cover_open()
{
	if (!flag_cover)
		return;
	for (int i = 0; i < kMaxThreads; i++) {
		thread_t* th = &threads[i];
		th->cover_fd = open("/sys/kernel/debug/kcov", O_RDWR);
		if (th->cover_fd == -1)
			fail("open of /sys/kernel/debug/kcov failed");
		if (ioctl(th->cover_fd, KCOV_INIT_TRACE, kCoverSize))
			fail("cover enable write failed");
		th->cover_data = (uintptr_t*)mmap(NULL, kCoverSize * sizeof(th->cover_data[0]), PROT_READ | PROT_WRITE, MAP_SHARED, th->cover_fd, 0);
		if ((void*)th->cover_data == MAP_FAILED)
			fail("cover mmap failed");
	}
}

void cover_enable(thread_t* th)
{
	if (!flag_cover)
		return;
	debug("#%d: enabling /sys/kernel/debug/kcov\n", th->id);
	if (ioctl(th->cover_fd, KCOV_ENABLE, 0))
		fail("cover enable write failed");
	debug("#%d: enabled /sys/kernel/debug/kcov\n", th->id);
}

void cover_reset(thread_t* th)
{
	if (!flag_cover)
		return;
	__atomic_store_n(&th->cover_data[0], 0, __ATOMIC_RELAXED);
}

uintptr_t cover_read(thread_t* th)
{
	if (!flag_cover)
		return 0;
	uintptr_t n = __atomic_load_n(&th->cover_data[0], __ATOMIC_RELAXED);
	debug("#%d: read cover = %d\n", th->id, n);
	if (n >= kCoverSize)
		fail("#%d: too much cover %d", th->id, n);
	if (flag_deduplicate) {
		n = cover_dedup(th, n);
		debug("#%d: dedup cover %d\n", th->id, n);
	}
	return n;
}

uintptr_t cover_dedup(thread_t* th, uintptr_t n)
{
	uintptr_t* cover_data = th->cover_data + 1;
	std::sort(cover_data, cover_data + n);
	uintptr_t w = 0;
	uintptr_t last = 0;
	for (uintptr_t i = 0; i < n; i++) {
		uintptr_t pc = cover_data[i];
		if (pc == last)
			continue;
		cover_data[w++] = last = pc;
	}
	return w;
}

void copyin(char* addr, uint64_t val, uint64_t size)
{
	switch (size) {
	case 1:
		*(uint8_t*)addr = val;
		break;
	case 2:
		*(uint16_t*)addr = val;
		break;
	case 4:
		*(uint32_t*)addr = val;
		break;
	case 8:
		*(uint64_t*)addr = val;
		break;
	default:
		fail("copyin: bad argument size %lu", size);
	}
}

uint64_t copyout(char* addr, uint64_t size)
{
	switch (size) {
	case 1:
		return *(uint8_t*)addr;
	case 2:
		return *(uint16_t*)addr;
	case 4:
		return *(uint32_t*)addr;
	case 8:
		return *(uint64_t*)addr;
	default:
		fail("copyout: bad argument size %lu", size);
	}
}

uint64_t read_arg(uint64_t** input_posp)
{
	uint64_t typ = read_input(input_posp);
	uint64_t size = read_input(input_posp);
	(void)size;
	uint64_t arg = 0;
	switch (typ) {
	case arg_const: {
		arg = read_input(input_posp);
		break;
	}
	case arg_result: {
		arg = read_result(input_posp);
		break;
	}
	default:
		fail("bad argument type %lu", typ);
	}
	return arg;
}

uint64_t read_result(uint64_t** input_posp)
{
	uint64_t idx = read_input(input_posp);
	uint64_t op_div = read_input(input_posp);
	uint64_t op_add = read_input(input_posp);
	if (idx >= kMaxCommands)
		fail("command refers to bad result %ld", idx);
	uint64_t arg = default_value;
	if (results[idx].executed) {
		arg = results[idx].val;
		if (op_div != 0)
			arg = arg / op_div;
		arg += op_add;
	}
	return arg;
}

uint64_t read_input(uint64_t** input_posp, bool peek)
{
	uint64_t* input_pos = *input_posp;
	if ((char*)input_pos >= input_data + kMaxInput)
		fail("input command overflows input");
	if (!peek)
		*input_posp = input_pos + 1;
	return *input_pos;
}

void write_output(uint32_t v)
{
	if (collide)
		return;
	if ((char*)output_pos >= output_data + kMaxOutput)
		fail("output overflow");
	*output_pos++ = v;
}

bool write_file(const char* file, const char* what, ...)
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

// One does not simply remove a directory.
// There can be mounts, so we need to try to umount.
// Moreover, a mount can be mounted several times, so we need to try to umount in a loop.
// Moreover, after umount a dir can become non-empty again, so we need another loop.
// Moreover, a mount can be re-mounted as read-only and then we will fail to make a dir empty.
void remove_dir(const char* dir)
{
	int iter = 0;
retry:
	DIR* dp = opendir(dir);
	if (dp == NULL)
		fail("opendir(%s) failed", dir);
	while (dirent* ep = readdir(dp)) {
		if (strcmp(ep->d_name, ".") == 0 || strcmp(ep->d_name, "..") == 0)
			continue;
		char filename[FILENAME_MAX];
		snprintf(filename, sizeof(filename), "%s/%s", dir, ep->d_name);
		struct stat st;
		if (lstat(filename, &st))
			fail("lstat(%s) failed", filename);
		if (S_ISDIR(st.st_mode)) {
			remove_dir(filename);
			continue;
		}
		for (int i = 0;; i++) {
			debug("unlink(%s)\n", filename);
			if (unlink(filename) == 0)
				break;
			if (errno == EROFS) {
				debug("ignoring EROFS\n");
				break;
			}
			if (errno != EBUSY || i > 100)
				fail("unlink(%s) failed", filename);
			debug("umount(%s)\n", filename);
			if (umount2(filename, MNT_DETACH))
				fail("umount(%s) failed", filename);
		}
	}
	closedir(dp);
	for (int i = 0;; i++) {
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
					fail("umount(%s) failed", dir);
				continue;
			}
			if (errno == ENOTEMPTY) {
				if (iter < 100) {
					iter++;
					goto retry;
				}
			}
		}
		fail("rmdir(%s) failed", dir);
	}
}

uint64_t current_time_ms()
{
	timespec ts;
	if (clock_gettime(CLOCK_MONOTONIC, &ts))
		fail("clock_gettime failed");
	return (uint64_t)ts.tv_sec * 1000 + (uint64_t)ts.tv_nsec / 1000000;
}

// logical error (e.g. invalid input program)
void fail(const char* msg, ...)
{
	int e = errno;
	fflush(stdout);
	va_list args;
	va_start(args, msg);
	vfprintf(stderr, msg, args);
	va_end(args);
	fprintf(stderr, " (errno %d)\n", e);
	exit(kFailStatus);
}

// kernel error (e.g. wrong syscall return value)
void error(const char* msg, ...)
{
	fflush(stdout);
	va_list args;
	va_start(args, msg);
	vfprintf(stderr, msg, args);
	va_end(args);
	fprintf(stderr, "\n");
	exit(kErrorStatus);
}

// just exit (e.g. due to temporal ENOMEM error)
void exitf(const char* msg, ...)
{
	int e = errno;
	fflush(stdout);
	va_list args;
	va_start(args, msg);
	vfprintf(stderr, msg, args);
	va_end(args);
	fprintf(stderr, " (errno %d)\n", e);
	exit(1);
}

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
