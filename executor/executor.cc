// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#include <algorithm>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/futex.h>
#include <linux/reboot.h>
#include <pthread.h>
#include <setjmp.h>
#include <signal.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/reboot.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include "syscalls.h"

#define SYZ_EXECUTOR
#include "common.h"

#define KCOV_INIT_TRACE _IOR('c', 1, unsigned long long)
#define KCOV_INIT_TABLE _IOR('c', 2, unsigned long long)
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

// We use the default value instead of results of failed syscalls.
// -1 is an invalid fd and an invalid address and deterministic,
// so good enough for our purposes.
const uint64_t default_value = -1;

enum sandbox_type {
	sandbox_none,
	sandbox_setuid,
	sandbox_namespace,
};

bool flag_cover;
bool flag_threaded;
bool flag_collide;
bool flag_deduplicate;
bool flag_sandbox_privs;
sandbox_type flag_sandbox;

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
	int id;
	pthread_t th;
	uint64_t* cover_data;
	uint64_t* copyout_pos;
	int ready;
	int done;
	bool handled;
	int call_n;
	int call_index;
	int call_num;
	int num_args;
	uintptr_t args[kMaxArgs];
	uint64_t res;
	uint64_t reserrno;
	uint64_t cover_size;
	int cover_fd;
};

thread_t threads[kMaxThreads];

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
void cover_open();
void cover_enable(thread_t* th);
void cover_reset(thread_t* th);
uint64_t cover_read(thread_t* th);
uint64_t cover_dedup(thread_t* th, uint64_t n);

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
	flag_sandbox = sandbox_none;
	if (flags & (1 << 5))
		flag_sandbox = sandbox_setuid;
	else if (flags & (1 << 6))
		flag_sandbox = sandbox_namespace;
	if (!flag_threaded)
		flag_collide = false;

	cover_open();
	setup_main_process();

	int pid = -1;
	switch (flag_sandbox) {
	case sandbox_none:
		pid = do_sandbox_none();
		break;
	case sandbox_setuid:
		pid = do_sandbox_setuid();
		break;
	case sandbox_namespace:
		pid = do_sandbox_namespace();
		break;
	default:
		fail("unknown sandbox type");
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
	// Loop can be killed by a test process with e.g.:
	// ptrace(PTRACE_SEIZE, 1, 0, 0x100040)
	// This is unfortunate, but I don't have a better solution than ignoring it for now.
	exitf("loop exited with status %d", status);
	return 0;
}

void loop()
{
	// Tell parent that we are ready to serve.
	char tmp;
	if (write(kOutPipeFd, &tmp, 1) != 1)
		fail("control pipe write failed");

	for (int iter = 0;; iter++) {
		// Create a new private work dir for this test (removed at the end of the loop).
		char cwdbuf[256];
		sprintf(cwdbuf, "./%d", iter);
		if (mkdir(cwdbuf, 0777))
			fail("failed to mkdir");

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
				NONFAILING(memcpy(addr, input_pos, size));
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
		for (uint64_t i = 0; i < th->cover_size; i++)
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
	th->res = execute_syscall(call->sys_nr, th->args[0], th->args[1], th->args[2], th->args[3], th->args[4], th->args[5], th->args[6], th->args[7], th->args[8]);
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
			fail("cover init write failed");
		th->cover_data = (uint64_t*)mmap(NULL, kCoverSize * sizeof(th->cover_data[0]), PROT_READ | PROT_WRITE, MAP_SHARED, th->cover_fd, 0);
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

uint64_t cover_read(thread_t* th)
{
	if (!flag_cover)
		return 0;
	uint64_t n = __atomic_load_n(&th->cover_data[0], __ATOMIC_RELAXED);
	debug("#%d: read cover = %d\n", th->id, n);
	if (n >= kCoverSize)
		fail("#%d: too much cover %d", th->id, n);
	if (flag_deduplicate) {
		n = cover_dedup(th, n);
		debug("#%d: dedup cover %d\n", th->id, n);
	}
	return n;
}

uint64_t cover_dedup(thread_t* th, uint64_t n)
{
	uint64_t* cover_data = th->cover_data + 1;
	std::sort(cover_data, cover_data + n);
	uint64_t w = 0;
	uint64_t last = 0;
	for (uint64_t i = 0; i < n; i++) {
		uint64_t pc = cover_data[i];
		if (pc == last)
			continue;
		cover_data[w++] = last = pc;
	}
	return w;
}

void copyin(char* addr, uint64_t val, uint64_t size)
{
	NONFAILING(switch (size) {
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
	});
}

uint64_t copyout(char* addr, uint64_t size)
{
	uint64_t res = default_value;
	NONFAILING(switch (size) {
		case 1:
			res = *(uint8_t*)addr;
			break;
		case 2:
			res = *(uint16_t*)addr;
			break;
		case 4:
			res = *(uint32_t*)addr;
			break;
		case 8:
			res = *(uint64_t*)addr;
			break;
		default:
			fail("copyout: bad argument size %lu", size);
	});
	return res;
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
