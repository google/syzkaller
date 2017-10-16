// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#include <algorithm>
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#ifndef GIT_REVISION
#define GIT_REVISION "unknown"
#endif

const int kMaxInput = 2 << 20;
const int kMaxOutput = 16 << 20;
const int kMaxArgs = 9;
const int kMaxThreads = 16;
const int kMaxCommands = 16 << 10;

const uint64_t instr_eof = -1;
const uint64_t instr_copyin = -2;
const uint64_t instr_copyout = -3;

const uint64_t arg_const = 0;
const uint64_t arg_result = 1;
const uint64_t arg_data = 2;
const uint64_t arg_csum = 3;

enum sandbox_type {
	sandbox_none,
	sandbox_setuid,
	sandbox_namespace,
};

bool flag_cover;
bool flag_threaded;
bool flag_collide;
bool flag_sandbox_privs;
sandbox_type flag_sandbox;
bool flag_enable_tun;
bool flag_enable_fault_injection;

bool flag_collect_cover;
bool flag_dedup_cover;

// If true, then executor should write the comparisons data to fuzzer.
bool flag_collect_comps;

// Inject fault into flag_fault_nth-th operation in flag_fault_call-th syscall.
bool flag_inject_fault;
int flag_fault_call;
int flag_fault_nth;

int running;
uint32_t completed;
bool collide;

// We use the default value instead of results of failed syscalls.
// -1 is an invalid fd and an invalid address and deterministic,
// so good enough for our purposes.
const uint64_t default_value = -1;

// Checksum kinds.
const uint64_t arg_csum_inet = 0;

// Checksum chunk kinds.
const uint64_t arg_csum_chunk_data = 0;
const uint64_t arg_csum_chunk_const = 1;

struct thread_t {
	bool created;
	int id;
	osthread_t th;
	// TODO(dvyukov): this assumes 64-bit kernel. This must be "kernel long" somehow.
	uint64_t* cover_data;
	// Pointer to the size of coverage (stored as first word of memory).
	uint64_t* cover_size_ptr;

	event_t ready;
	event_t done;
	uint64_t* copyout_pos;
	bool handled;
	int call_n;
	int call_index;
	int call_num;
	int num_args;
	long args[kMaxArgs];
	long res;
	uint32_t reserrno;
	uint64_t cover_size;
	bool fault_injected;
	int cover_fd;
};

thread_t threads[kMaxThreads];

struct res_t {
	bool executed;
	uint64_t val;
};

res_t results[kMaxCommands];

enum {
	KCOV_CMP_CONST = 1,
	KCOV_CMP_SIZE1 = 0,
	KCOV_CMP_SIZE2 = 2,
	KCOV_CMP_SIZE4 = 4,
	KCOV_CMP_SIZE8 = 6,
	KCOV_CMP_SIZE_MASK = 6,
};

struct kcov_comparison_t {
	uint64_t type;
	uint64_t arg1;
	uint64_t arg2;
	uint64_t pc;

	// Writes the structure using the write_one function for each field.
	// Inspired by write_output() function.
	void write(uint32_t* (*write_one)(uint32_t));
	bool operator==(const struct kcov_comparison_t& other) const;
	bool operator<(const struct kcov_comparison_t& other) const;
};

long execute_syscall(call_t* c, long a0, long a1, long a2, long a3, long a4, long a5, long a6, long a7, long a8);
thread_t* schedule_call(int n, int call_index, int call_num, uint64_t num_args, uint64_t* args, uint64_t* pos);
void handle_completion(thread_t* th);
void execute_call(thread_t* th);
void thread_create(thread_t* th, int id);
void* worker_thread(void* arg);
uint32_t* write_output(uint32_t v);
void write_completed(uint32_t completed);
uint64_t read_input(uint64_t** input_posp, bool peek = false);
uint64_t read_arg(uint64_t** input_posp);
uint64_t read_result(uint64_t** input_posp);
void copyin(char* addr, uint64_t val, uint64_t size, uint64_t bf_off, uint64_t bf_len);
uint64_t copyout(char* addr, uint64_t size);
void cover_open();
void cover_enable(thread_t* th);
void cover_reset(thread_t* th);
uint64_t read_cover_size(thread_t* th);
static uint32_t hash(uint32_t a);
static bool dedup(uint32_t sig);

void execute_one(uint64_t* input_data)
{
retry:
	uint64_t* input_pos = input_data;
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
				uint64_t bf_off = read_input(&input_pos);
				uint64_t bf_len = read_input(&input_pos);
				copyin(addr, arg, size, bf_off, bf_len);
				break;
			}
			case arg_result: {
				uint64_t val = read_result(&input_pos);
				copyin(addr, val, size, 0, 0);
				break;
			}
			case arg_data: {
				NONFAILING(memcpy(addr, input_pos, size));
				// Read out the data.
				for (uint64_t i = 0; i < (size + 7) / 8; i++)
					read_input(&input_pos);
				break;
			}
			case arg_csum: {
				debug("checksum found at %llx\n", addr);
				char* csum_addr = addr;
				uint64_t csum_size = size;
				uint64_t csum_kind = read_input(&input_pos);
				switch (csum_kind) {
				case arg_csum_inet: {
					if (csum_size != 2) {
						fail("inet checksum must be 2 bytes, not %lu", size);
					}
					debug("calculating checksum for %llx\n", csum_addr);
					struct csum_inet csum;
					csum_inet_init(&csum);
					uint64_t chunks_num = read_input(&input_pos);
					uint64_t chunk;
					for (chunk = 0; chunk < chunks_num; chunk++) {
						uint64_t chunk_kind = read_input(&input_pos);
						uint64_t chunk_value = read_input(&input_pos);
						uint64_t chunk_size = read_input(&input_pos);
						switch (chunk_kind) {
						case arg_csum_chunk_data:
							debug("#%d: data chunk, addr: %llx, size: %llu\n", chunk, chunk_value, chunk_size);
							NONFAILING(csum_inet_update(&csum, (const uint8_t*)chunk_value, chunk_size));
							break;
						case arg_csum_chunk_const:
							if (chunk_size != 2 && chunk_size != 4 && chunk_size != 8) {
								fail("bad checksum const chunk size %lld\n", chunk_size);
							}
							// Here we assume that const values come to us big endian.
							debug("#%d: const chunk, value: %llx, size: %llu\n", chunk, chunk_value, chunk_size);
							csum_inet_update(&csum, (const uint8_t*)&chunk_value, chunk_size);
							break;
						default:
							fail("bad checksum chunk kind %lu", chunk_kind);
						}
					}
					int16_t csum_value = csum_inet_digest(&csum);
					debug("writing inet checksum %hx to %llx\n", csum_value, csum_addr);
					NONFAILING(copyin(csum_addr, csum_value, 2, 0, 0));
					break;
				}
				default:
					fail("bad checksum kind %lu", csum_kind);
				}
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
		if (call_num >= syscall_count)
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
			// Note: sys knows about this 20ms timeout when it generates
			// timespec/timeval values.
			const uint64_t timeout_ms = flag_debug ? 500 : 20;
			if (event_timedwait(&th->done, timeout_ms))
				handle_completion(th);
			// Check if any of previous calls have completed.
			// Give them some additional time, because they could have been
			// just unblocked by the current call.
			if (running < 0)
				fail("running = %d", running);
			if (running > 0) {
				bool last = read_input(&input_pos, true) == instr_eof;
				sleep_ms(last ? 10 : 1);
				for (int i = 0; i < kMaxThreads; i++) {
					th = &threads[i];
					if (!th->handled && event_isset(&th->done))
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

	if (flag_collide && !flag_inject_fault && !collide) {
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
		if (event_isset(&th->done)) {
			if (!th->handled)
				handle_completion(th);
			break;
		}
	}
	if (i == kMaxThreads)
		exitf("out of threads");
	thread_t* th = &threads[i];
	debug("scheduling call %d [%s] on thread %d\n", call_index, syscalls[call_num].name, th->id);
	if (event_isset(&th->ready) || !event_isset(&th->done) || !th->handled)
		fail("bad thread state in schedule: ready=%d done=%d handled=%d",
		     event_isset(&th->ready), event_isset(&th->done), th->handled);
	th->copyout_pos = pos;
	event_reset(&th->done);
	th->handled = false;
	th->call_n = n;
	th->call_index = call_index;
	th->call_num = call_num;
	th->num_args = num_args;
	for (int i = 0; i < kMaxArgs; i++)
		th->args[i] = args[i];
	event_set(&th->ready);
	running++;
	return th;
}

void handle_completion(thread_t* th)
{
	debug("completion of call %d [%s] on thread %d\n", th->call_index, syscalls[th->call_num].name, th->id);
	if (event_isset(&th->ready) || !event_isset(&th->done) || th->handled)
		fail("bad thread state in completion: ready=%d done=%d handled=%d",
		     event_isset(&th->ready), event_isset(&th->done), th->handled);
	if (th->res != (long)-1) {
		if (th->call_n >= kMaxCommands)
			fail("result idx %ld overflows kMaxCommands", th->call_n);
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
				if (th->call_n >= kMaxCommands)
					fail("result idx %ld overflows kMaxCommands", th->call_n);
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
		uint32_t reserrno = th->res != (uint32_t)-1 ? 0 : th->reserrno;
		write_output(reserrno);
		write_output(th->fault_injected);
		uint32_t* signal_count_pos = write_output(0); // filled in later
		uint32_t* cover_count_pos = write_output(0); // filled in later
		uint32_t* comps_count_pos = write_output(0); // filled in later
		uint32_t nsig = 0, cover_size = 0, comps_size = 0;

		if (flag_collect_comps) {
			// Collect only the comparisons
			comps_size = th->cover_size;
			kcov_comparison_t* start = (kcov_comparison_t*)th->cover_data;
			kcov_comparison_t* end = start + comps_size;
			std::sort(start, end);
			comps_size = std::unique(start, end) - start;
			for (uint32_t i = 0; i < comps_size; ++i)
				start[i].write(write_output);
		} else {
			// Write out feedback signals.
			// Currently it is code edges computed as xor of
			// two subsequent basic block PCs.
			uint32_t prev = 0;
			for (uint32_t i = 0; i < th->cover_size; i++) {
				uint32_t pc = (uint32_t)th->cover_data[i];
				uint32_t sig = pc ^ prev;
				prev = hash(pc);
				if (dedup(sig))
					continue;
				write_output(sig);
				nsig++;
			}
			if (flag_collect_cover) {
				// Write out real coverage (basic block PCs).
				cover_size = th->cover_size;
				if (flag_dedup_cover) {
					uint64_t* start = (uint64_t*)th->cover_data;
					uint64_t* end = start + cover_size;
					std::sort(start, end);
					cover_size = std::unique(start, end) - start;
				}
				// Truncate PCs to uint32_t assuming that they fit into 32-bits.
				// True for x86_64 and arm64 without KASLR.
				for (uint32_t i = 0; i < cover_size; i++)
					write_output((uint32_t)th->cover_data[i]);
			}
		}
		// Write out real coverage (basic block PCs).
		*cover_count_pos = cover_size;
		// Write out number of comparisons
		*comps_count_pos = comps_size;
		// Write out number of signals
		*signal_count_pos = nsig;
		debug("out #%u: index=%u num=%u errno=%d sig=%u cover=%u comps=%u\n",
		      completed, th->call_index, th->call_num, reserrno, nsig,
		      cover_size, comps_size);
		completed++;
		write_completed(completed);
	}
	th->handled = true;
	running--;
}

void thread_create(thread_t* th, int id)
{
	th->created = true;
	th->id = id;
	th->handled = true;
	event_init(&th->ready);
	event_init(&th->done);
	event_set(&th->done);
	if (flag_threaded)
		thread_start(&th->th, worker_thread, th);
}

void* worker_thread(void* arg)
{
	thread_t* th = (thread_t*)arg;

	cover_enable(th);
	for (;;) {
		event_wait(&th->ready);
		execute_call(th);
	}
	return 0;
}

void execute_call(thread_t* th)
{
	event_reset(&th->ready);
	call_t* call = &syscalls[th->call_num];
	debug("#%d: %s(", th->id, call->name);
	for (int i = 0; i < th->num_args; i++) {
		if (i != 0)
			debug(", ");
		debug("0x%lx", th->args[i]);
	}
	debug(")\n");

	int fail_fd = -1;
	if (flag_inject_fault && th->call_index == flag_fault_call) {
		if (collide)
			fail("both collide and fault injection are enabled");
		debug("injecting fault into %d-th operation\n", flag_fault_nth);
		fail_fd = inject_fault(flag_fault_nth);
	}

	cover_reset(th);
	th->res = execute_syscall(call, th->args[0], th->args[1], th->args[2],
				  th->args[3], th->args[4], th->args[5],
				  th->args[6], th->args[7], th->args[8]);
	th->reserrno = errno;
	th->cover_size = read_cover_size(th);
	th->fault_injected = false;

	if (flag_inject_fault && th->call_index == flag_fault_call) {
		th->fault_injected = fault_injected(fail_fd);
		debug("fault injected: %d\n", th->fault_injected);
	}

	if (th->res == (uint32_t)-1)
		debug("#%d: %s = errno(%d)\n", th->id, call->name, th->reserrno);
	else
		debug("#%d: %s = 0x%lx\n", th->id, call->name, th->res);
	event_set(&th->done);
}

static uint32_t hash(uint32_t a)
{
	a = (a ^ 61) ^ (a >> 16);
	a = a + (a << 3);
	a = a ^ (a >> 4);
	a = a * 0x27d4eb2d;
	a = a ^ (a >> 15);
	return a;
}

const uint32_t dedup_table_size = 8 << 10;
uint32_t dedup_table[dedup_table_size];

// Poorman's best-effort hashmap-based deduplication.
// The hashmap is global which means that we deduplicate across different calls.
// This is OK because we are interested only in new signals.
static bool dedup(uint32_t sig)
{
	for (uint32_t i = 0; i < 4; i++) {
		uint32_t pos = (sig + i) % dedup_table_size;
		if (dedup_table[pos] == sig)
			return true;
		if (dedup_table[pos] == 0) {
			dedup_table[pos] = sig;
			return false;
		}
	}
	dedup_table[sig % dedup_table_size] = sig;
	return false;
}

void copyin(char* addr, uint64_t val, uint64_t size, uint64_t bf_off, uint64_t bf_len)
{
	NONFAILING(switch (size) {
		case 1:
			STORE_BY_BITMASK(uint8_t, addr, val, bf_off, bf_len);
			break;
		case 2:
			STORE_BY_BITMASK(uint16_t, addr, val, bf_off, bf_len);
			break;
		case 4:
			STORE_BY_BITMASK(uint32_t, addr, val, bf_off, bf_len);
			break;
		case 8:
			STORE_BY_BITMASK(uint64_t, addr, val, bf_off, bf_len);
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
		// Bitfields can't be args of a normal syscall, so just ignore them.
		read_input(input_posp); // bit field offset
		read_input(input_posp); // bit field length
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
	//if ((char*)input_pos >= input_data + kMaxInput)
	//	fail("input command overflows input");
	if (!peek)
		*input_posp = input_pos + 1;
	return *input_pos;
}

void kcov_comparison_t::write(uint32_t* (*write_one)(uint32_t))
{
	// Write order: type arg1 arg2 pc.
	write_one((uint32_t)type);

	// KCOV converts all arguments of size x first to uintx_t and then to
	// uint64_t. We want to properly extend signed values, e.g we want
	// int8_t c = 0xfe to be represented as 0xfffffffffffffffe.
	// Note that uint8_t c = 0xfe will be represented the same way.
	// This is ok because during hints processing we will anyways try
	// the value 0x00000000000000fe.
	switch (type & KCOV_CMP_SIZE_MASK) {
	case KCOV_CMP_SIZE1:
		arg1 = (uint64_t)(int64_t)(int8_t)arg1;
		arg2 = (uint64_t)(int64_t)(int8_t)arg2;
		break;
	case KCOV_CMP_SIZE2:
		arg1 = (uint64_t)(int64_t)(int16_t)arg1;
		arg2 = (uint64_t)(int64_t)(int16_t)arg2;
		break;
	case KCOV_CMP_SIZE4:
		arg1 = (uint64_t)(int64_t)(int32_t)arg1;
		arg2 = (uint64_t)(int64_t)(int32_t)arg2;
		break;
	}
	bool is_size_8 = (type & KCOV_CMP_SIZE_MASK) == KCOV_CMP_SIZE8;
	if (!is_size_8) {
		write_one((uint32_t)arg1);
		write_one((uint32_t)arg2);
		return;
	}
	// If we have 64 bits arguments then write them in Little-endian.
	write_one((uint32_t)(arg1 & 0xFFFFFFFF));
	write_one((uint32_t)(arg1 >> 32));
	write_one((uint32_t)(arg2 & 0xFFFFFFFF));
	write_one((uint32_t)(arg2 >> 32));
}

bool kcov_comparison_t::operator==(const struct kcov_comparison_t& other) const
{
	return type == other.type && arg1 == other.arg1 && arg2 == other.arg2 && pc == other.pc;
}

bool kcov_comparison_t::operator<(const struct kcov_comparison_t& other) const
{
	if (type != other.type)
		return type < other.type;
	if (arg1 != other.arg1)
		return arg1 < other.arg1;
	if (arg2 != other.arg2)
		return arg2 < other.arg2;
	return pc < other.pc;
}
