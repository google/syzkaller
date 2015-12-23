// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#include <algorithm>
#include <errno.h>
#include <fcntl.h>
#include <grp.h>
#include <limits.h>
#include <linux/futex.h>
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
const int kCoverFd = 5;
const int kMaxInput = 2 << 20;
const int kMaxOutput = 16 << 20;
const int kMaxArgs = 9;
const int kMaxThreads = 16;
const int kMaxCommands = 4 << 10;
const int kCoverSize = 16 << 10;

const uint64_t instr_eof = -1;
const uint64_t instr_copyin = -2;
const uint64_t instr_copyout = -3;
const uint64_t instr_set_pad = -4;
const uint64_t instr_check_pad = -5;

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
bool flag_no_setpgid;

__attribute__((aligned(64 << 10))) char input_data[kMaxInput];
__attribute__((aligned(64 << 10))) char output_data[kMaxOutput];
uint32_t* output_pos;
int completed;
int running;
bool collide;

struct res_t {
	bool executed;
	uint64_t val;
};

res_t results[kMaxCommands];

struct thread_t {
	bool created;
	bool root;
	int id;
	pthread_t th;
	uint32_t* cover_data;
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
	uint32_t cover_size;
	int cover_fd;
};

thread_t threads[kMaxThreads];

__attribute__((noreturn)) void fail(const char* msg, ...);
__attribute__((noreturn)) void error(const char* msg, ...);
__attribute__((noreturn)) void exitf(const char* msg, ...);
void debug(const char* msg, ...);
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
void thread_create(thread_t* th, int id, bool root);
void* worker_thread(void* arg);
uint64_t current_time_ms();
void cover_open();
void cover_enable(thread_t* th);
void cover_reset(thread_t* th);
uint32_t cover_read(thread_t* th);
uint32_t cover_dedup(thread_t* th, uint32_t n);

int main()
{
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
	char cwdbuf[64 << 10];
	char* cwd = getcwd(cwdbuf, sizeof(cwdbuf));

	sigset_t sigchldset;
	sigemptyset(&sigchldset);
	sigaddset(&sigchldset, SIGCHLD);
	if (sigprocmask(SIG_BLOCK, &sigchldset, NULL))
		fail("sigprocmask failed");

	uint64_t flags = *(uint64_t*)input_data;
	flag_debug = flags & (1 << 0);
	flag_cover = flags & (1 << 1);
	flag_threaded = flags & (1 << 2);
	flag_collide = flags & (1 << 3);
	flag_deduplicate = flags & (1 << 4);
	flag_drop_privs = flags & (1 << 5);
	flag_no_setpgid = flags & (1 << 6);
	if (!flag_threaded)
		flag_collide = false;

	cover_open();

	for (;;) {
		char tmp;
		if (read(kInPipeFd, &tmp, 1) != 1)
			fail("control pipe read failed");
		debug("received start command\n");
		// The dir may have been recreated.
		if (chdir(cwd))
			fail("failed to chdir");

		int pid = fork();
		if (pid < 0)
			fail("fork failed");
		if (pid == 0) {
			if (!flag_no_setpgid)
				setpgid(0, 0);
			unshare(CLONE_NEWNS);
			close(kInPipeFd);
			close(kOutPipeFd);
			if (flag_drop_privs) {
				// Pre-create one thread with root privileges for execution of special syscalls (e.g. mount).
				if (flag_threaded)
					thread_create(&threads[kMaxThreads - 1], kMaxThreads - 1, true);
				// TODO: 65534 is meant to be nobody
				if (setgroups(0, NULL))
					fail("failed to setgroups");
				// glibc versions do not we want -- they force all threads to setuid.
				// We want to preserve the thread above as root.
				if (syscall(SYS_setresgid, 65534, 65534, 65534))
					fail("failed to setresgid");
				if (syscall(SYS_setresuid, 65534, 65534, 65534))
					fail("failed to setresuid");
			}
			// Don't need that SIGCANCEL/SIGSETXID glibc stuff.
			// SIGCANCEL sent to main thread causes it to exit
			// without bringing down the whole group.
			struct sigaction sa;
			memset(&sa, 0, sizeof(sa));
			sa.sa_handler = SIG_IGN;
			syscall(SYS_rt_sigaction, 0x20, &sa, NULL, 8);
			syscall(SYS_rt_sigaction, 0x21, &sa, NULL, 8);

			execute_one();

			debug("exiting\n");
			return 0;
		}

		int status = 0;
		if (!flag_no_setpgid) {
			timespec ts = {};
			ts.tv_sec = 5;
			ts.tv_nsec = 0;
			if (sigtimedwait(&sigchldset, NULL, &ts) < 0) {
				debug("sigtimedwait expired, killing %d\n", pid);
				if (!flag_no_setpgid)
					kill(-pid, SIGKILL);
				kill(pid, SIGKILL);
			}
			debug("waitpid(%d)\n", pid);
			if (waitpid(pid, &status, __WALL | WUNTRACED) != pid)
				fail("waitpid failed");
			debug("waitpid(%d) returned\n", pid);
			// Drain SIGCHLD signals.
			ts.tv_sec = 0;
			ts.tv_nsec = 0;
			while (sigtimedwait(&sigchldset, NULL, &ts) > 0) {
			}
		}
		else {
			// This code is less efficient, but does not require working sigtimedwait.
			// We've hit 2 systems that mishandle sigtimedwait.
			uint64_t start = current_time_ms();
			for (;;) {
				int res = waitpid(pid, &status, __WALL | WUNTRACED | WNOHANG);
				debug("waitpid(%d)=%d (%d)\n", pid, res, errno);
				if (res == pid)
					break;
				usleep(1000);
				if (current_time_ms() - start > 5 * 1000) {
					debug("killing\n");
					kill(-pid, SIGKILL);
					kill(pid, SIGKILL);
					int res = waitpid(pid, &status, __WALL | WUNTRACED);
					debug("waitpid(%d)=%d (%d)\n", pid, res, errno);
					if (res == pid)
						break;
					fail("waitpid failed");
				}
			}
		}
		status = WEXITSTATUS(status);
		if (status == kFailStatus)
			fail("child failed");
		if (status == kErrorStatus)
			error("child errored");
		if (write(kOutPipeFd, &tmp, 1) != 1)
			fail("control pipe write failed");
	}
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
		if (call_num == instr_set_pad) {
			char* addr = (char*)read_input(&input_pos); // addr
			uint64_t size = read_input(&input_pos);     // size
			memset(addr, 0, size);
			continue;
		}
		if (call_num == instr_check_pad) {
			read_input(&input_pos); // addr
			read_input(&input_pos); // size
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
		}
		else if (flag_threaded) {
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
		}
		else {
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
	// Figure out whether we need root privs for this call.
	bool root = false;
	switch (syscalls[call_num].sys_nr) {
	case __NR_mount:
	case __NR_umount2:
	case __NR_syz_fuse_mount:
	case __NR_syz_fuseblk_mount:
		root = true;
	}
	// Find a spare thread to execute the call.
	int i;
	for (i = 0; i < kMaxThreads; i++) {
		thread_t* th = &threads[i];
		if (!th->created)
			thread_create(th, i, false);
		if (__atomic_load_n(&th->done, __ATOMIC_ACQUIRE)) {
			if (!th->handled)
				handle_completion(th);
			if (flag_drop_privs && root != th->root)
				continue;
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
	uint64_t* copyout_pos = th->copyout_pos;
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
			case instr_check_pad: {
				// Ignore for now, we will process them below.
				read_input(&th->copyout_pos);
				read_input(&th->copyout_pos);
				break;
			}
			default:
				done = true;
				break;
			}
		}
	}
	if (!collide) {
		th->copyout_pos = copyout_pos;
		for (bool done = false; !done;) {
			uint64_t call_num = read_input(&th->copyout_pos);
			switch (call_num) {
			case instr_copyout: {
				// Ignore, this is already handled above.
				read_input(&th->copyout_pos);
				read_input(&th->copyout_pos);
				break;
			}
			case instr_check_pad: {
				// Check that kernel returns zeros in struct padding.
				// Non-zeros can mean an information leak.
				char* addr = (char*)read_input(&th->copyout_pos);
				uint64_t size = read_input(&th->copyout_pos);
				for (uint64_t i = 0; i < size; i++) {
					if (addr[i] != 0) {
						printf("syscall '%s' (index %d): non-zero padding output at %p:",
						       syscalls[th->call_num].name, th->call_index, addr);
						for (i = 0; i < size; i++)
							printf(" %02x", addr[i]);
						printf("\n");
						error("non-zero padding");
					}
				}
				break;
			}
			default:
				done = true;
				break;
			}
		}

		write_output(th->call_index);
		write_output(th->call_num);
		write_output(th->res != (uint64_t)-1 ? 0 : th->reserrno);
		write_output(th->cover_size);
		for (uint32_t i = 0; i < th->cover_size; i++)
			write_output(th->cover_data[i + 1]);
		completed++;
		__atomic_store_n((uint32_t*)&output_data[0], completed, __ATOMIC_RELEASE);
	}
	th->handled = true;
	running--;
}

void thread_create(thread_t* th, int id, bool root)
{
	th->created = true;
	th->id = id;
	th->root = root;
	th->done = true;
	th->handled = true;
	if (flag_threaded) {
		if (pthread_create(&th->th, 0, worker_thread, th))
			exitf("pthread_create failed");
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
	case __NR_syz_openpts: {
		// syz_openpts(fd fd[tty], flags flags[open_flags]) fd[tty]
		int ptyno = 0;
		if (ioctl(th->args[0], TIOCGPTN, &ptyno) == 0) {
			char buf[128];
			sprintf(buf, "/dev/pts/%d", ptyno);
			th->res = open(buf, th->args[1], 0);
		}
		else {
			th->res = -1;
		}
	}
	case __NR_syz_dri_open: {
		// syz_dri_open(card_id intptr, flags flags[open_flags]) fd[dri]
		char buf[128];
		sprintf(buf, "/dev/dri/card%lu", th->args[0]);
		th->res = open(buf, th->args[1], 0);
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
			if (syscall(SYS_mknod, blkdev, S_IFBLK, makedev(7, 199)) == 0) {
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
		th->cover_data = (uint32_t*)mmap(NULL, kCoverSize * sizeof(th->cover_data[0]), PROT_READ | PROT_WRITE, MAP_SHARED, th->cover_fd, 0);
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

uint32_t cover_read(thread_t* th)
{
	if (!flag_cover)
		return 0;
	uint32_t n = __atomic_load_n(&th->cover_data[0], __ATOMIC_RELAXED);
	debug("#%d: read cover = %d\n", th->id, n);
	if (n >= kCoverSize)
		fail("#%d: too much cover %d", th->id, n);
	if (flag_deduplicate) {
		n = cover_dedup(th, n);
		debug("#%d: dedup cover %d\n", th->id, n);
	}
	return n;
}

uint32_t cover_dedup(thread_t* th, uint32_t n)
{
	uint32_t* cover_data = th->cover_data + 1;
	std::sort(cover_data, cover_data + n);
	uint32_t w = 0;
	uint32_t last = 0;
	for (uint32_t i = 0; i < n; i++) {
		uint32_t pc = cover_data[i];
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
	fflush(stdout);
	va_list args;
	va_start(args, msg);
	vfprintf(stderr, msg, args);
	va_end(args);
	fprintf(stderr, "\n");
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
