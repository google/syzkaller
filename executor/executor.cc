// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <pthread.h>
#include "syscalls.h"

const int kInFd = 3;
const int kOutFd = 4;
const int kMaxInput = 1 << 20;
const int kMaxOutput = 16 << 20;
const int kMaxArgs = 6;
const int kMaxThreads = 16;
const int kMaxCommands = 4 << 10;

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

bool flag_debug;
bool flag_cover;
bool flag_threaded;

__attribute__((aligned(64 << 10))) char input_data[kMaxInput];
__attribute__((aligned(64 << 10))) char output_data[kMaxOutput];
uint32_t* output_pos;
int completed;

struct res_t {
	bool executed;
	uint64_t val;
};

res_t results[kMaxCommands];

struct thread_t {
	bool created;
	int id;
	pthread_t th;
	int cover_fd;
	uint32_t cover_data[16 << 10];
	uint64_t* copyout_pos;
	bool ready;
	bool done;
	bool handled;
	int call_n;
	int call_index;
	int call_num;
	int num_args;
	uint64_t args[kMaxArgs];
	uint64_t res;
	int cover_size;
};

thread_t threads[kMaxThreads];

__attribute__((noreturn)) void fail(const char* msg, ...);
__attribute__((noreturn)) void error(const char* msg, ...);
void debug(const char* msg, ...);
uint64_t read_input(uint64_t** input_posp);
uint64_t read_arg(uint64_t** input_posp);
uint64_t read_result(uint64_t** input_posp);
void write_output(uint32_t v);
void copyin(char* addr, uint64_t val, uint64_t size);
uint64_t copyout(char* addr, uint64_t size);
thread_t* schedule_call(int n, int call_index, int call_num, uint64_t num_args, uint64_t* args, uint64_t* pos);
void execute_call(thread_t* th);
void handle_completion(thread_t* th);
void* worker_thread(void* arg);
uint64_t current_time_ms();
void cover_init(thread_t* th);
void cover_reset(thread_t* th);
int cover_read(thread_t* th);

int main()
{
	if (mmap(&input_data[0], kMaxInput, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_FIXED, kInFd, 0) != &input_data[0])
		fail("mmap of input file failed");
	if (mmap(&output_data[0], kMaxOutput, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_FIXED, kOutFd, 0) != &output_data[0])
		fail("mmap of output file failed");
	uint64_t* input_pos = (uint64_t*)&input_data[0];
	uint64_t flags = read_input(&input_pos);
	flag_debug = flags & (1 << 0);
	flag_cover = flags & (1 << 1);
	flag_threaded = flags & (1 << 2);
	output_pos = (uint32_t*)&output_data[0];
	write_output(0); // Number of executed syscalls (updated later).

	if (!flag_threaded)
		cover_init(&threads[0]);

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

		if (flag_threaded) {
			// Wait for call completion.
			uint64_t start = current_time_ms();
			while (!__atomic_load_n(&th->done, __ATOMIC_ACQUIRE) && (current_time_ms() - start) < 100)
				usleep(10);
			if (__atomic_load_n(&th->done, __ATOMIC_ACQUIRE))
				handle_completion(th);
			// Check if any of previous calls have completed.
			usleep(100);
			for (int i = 0; i < kMaxThreads; i++) {
				th = &threads[i];
				if (__atomic_load_n(&th->done, __ATOMIC_ACQUIRE) && !th->handled)
					handle_completion(th);
			}
		} else {
			// Execute directly.
			if (th != &threads[0])
				fail("using non-main thread in non-thread mode");
			execute_call(th);
			handle_completion(th);
		}
	}

	// TODO: handle hanged threads.
	debug("exiting\n");
	return 0;
}

thread_t* schedule_call(int n, int call_index, int call_num, uint64_t num_args, uint64_t* args, uint64_t* pos)
{
	// Find a spare thread to execute the call.
	thread_t* th = 0;
	for (int i = 0; i < kMaxThreads; i++) {
		th = &threads[i];
		if (!th->created) {
			th->created = true;
			th->id = i;
			th->done = true;
			th->handled = true;
			if (flag_threaded) {
				if (pthread_create(&th->th, 0, worker_thread, th))
					fail("pthread_create failed");
			}
		}
		if (__atomic_load_n(&th->done, __ATOMIC_ACQUIRE)) {
			if (!th->handled)
				handle_completion(th);
			break;
		}
	}
	if (th == &threads[kMaxThreads])
		fail("out of threads");
	debug("scheduling call %d [%s] on thread %d\n", call_index, syscalls[call_num].name, th->id);
	if (th->ready || !th->done || !th->handled)
		fail("bad thread state in schedule: ready=%d done=%d handled=%d",
		     th->ready, th->done, th->handled);
	th->copyout_pos = pos;
	th->done = false;
	th->handled = false;
	th->call_n = n;
	th->call_index = call_index;
	th->call_num = call_num;
	th->num_args = num_args;
	for (int i = 0; i < kMaxArgs; i++)
		th->args[i] = args[i];
	__atomic_store_n(&th->ready, true, __ATOMIC_RELEASE);
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
		for (;;) {
			th->call_n++;
			uint64_t call_num = read_input(&th->copyout_pos);
			if (call_num != instr_copyout)
				break;
			char* addr = (char*)read_input(&th->copyout_pos);
			uint64_t size = read_input(&th->copyout_pos);
			uint64_t val = copyout(addr, size);
			results[th->call_n].executed = true;
			results[th->call_n].val = val;
			debug("copyout from %p\n", addr);
		}
	}
	write_output(th->call_index);
	write_output(th->call_num);
	write_output(th->cover_size);
	for (int i = 0; i < th->cover_size; i++)
		write_output(th->cover_data[i]);
	completed++;
	__atomic_store_n((uint32_t*)&output_data[0], completed, __ATOMIC_RELEASE);
	th->handled = true;
}

void* worker_thread(void* arg)
{
	thread_t* th = (thread_t*)arg;

	cover_init(th);
	for (;;) {
		while (!__atomic_load_n(&th->ready, __ATOMIC_ACQUIRE))
			usleep(10);
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

	if (kMaxArgs != 6)
		fail("inconsistent number of arguments");

	cover_reset(th);
	th->res = syscall(call->sys_nr, th->args[0], th->args[1], th->args[2], th->args[3], th->args[4], th->args[5]);
	int errno0 = errno;
	th->cover_size = cover_read(th);

	if (th->res == (uint64_t)-1)
		debug("#%d: %s = errno(%d)\n", th->id, call->name, errno0);
	else
		debug("#%d: %s = %lx\n", th->id, call->name, th->res);
	__atomic_store_n(&th->done, true, __ATOMIC_RELEASE);
}

void cover_init(thread_t* th)
{
	if (!flag_cover)
		return;
	debug("#%d: opening /proc/cover\n", th->id);
	th->cover_fd = open("/proc/cover", O_RDWR);
	if (th->cover_fd == -1)
		fail("open of /proc/cover failed");
	char cmd[128];
	sprintf(cmd, "enable=%d", (int)(sizeof(th->cover_data) / sizeof(th->cover_data[0])));
	int n = write(th->cover_fd, cmd, strlen(cmd));
	if (n != (int)strlen(cmd))
		fail("cover enable write failed");
	debug("#%d: opened /proc/cover\n", th->id);
}

void cover_reset(thread_t* th)
{
	if (!flag_cover)
		return;
	debug("#%d: resetting /proc/cover\n", th->id);
	int n = write(th->cover_fd, "reset", sizeof("reset") - 1);
	if (n != sizeof("reset") - 1)
		fail("cover reset write failed");
}

int cover_read(thread_t* th)
{
	if (!flag_cover)
		return 0;
	int n = read(th->cover_fd, th->cover_data, sizeof(th->cover_data));
	if (n < 0 || n > (int)sizeof(th->cover_data) || (n % sizeof(th->cover_data[0])) != 0)
		fail("cover read failed after %s (n=%d)", syscalls[th->call_num].name, n);
	n /= sizeof(th->cover_data[0]);
	debug("#%d: read /proc/cover = %d\n", th->id, n);
	return n;
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

uint64_t read_input(uint64_t** input_posp)
{
	uint64_t* input_pos = *input_posp;
	if ((char*)input_pos >= input_data + kMaxInput)
		fail("input command overflows input");
	*input_posp = input_pos + 1;
	return *input_pos;
}

void write_output(uint32_t v)
{
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
	exit(67);
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
	exit(68);
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
