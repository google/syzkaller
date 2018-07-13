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

#ifndef GOOS
#define GOOS "unknown"
#endif

const int kMaxInput = 2 << 20;
const int kMaxOutput = 16 << 20;
const int kCoverSize = 256 << 10;
const int kMaxArgs = 9;
const int kMaxThreads = 16;
const int kMaxCommands = 1000;

const uint64 instr_eof = -1;
const uint64 instr_copyin = -2;
const uint64 instr_copyout = -3;

const uint64 arg_const = 0;
const uint64 arg_result = 1;
const uint64 arg_data = 2;
const uint64 arg_csum = 3;

const uint64 binary_format_native = 0;
const uint64 binary_format_bigendian = 1;
const uint64 binary_format_strdec = 2;
const uint64 binary_format_strhex = 3;
const uint64 binary_format_stroct = 4;

const uint64 no_copyout = -1;

enum sandbox_type {
	sandbox_none,
	sandbox_setuid,
	sandbox_namespace,
};

bool flag_cover;
bool flag_sandbox_privs;
sandbox_type flag_sandbox;
bool flag_enable_tun;
bool flag_enable_net_dev;
bool flag_enable_fault_injection;

bool flag_collect_cover;
bool flag_dedup_cover;
bool flag_threaded;
bool flag_collide;

// If true, then executor should write the comparisons data to fuzzer.
bool flag_collect_comps;

// Inject fault into flag_fault_nth-th operation in flag_fault_call-th syscall.
bool flag_inject_fault;
int flag_fault_call;
int flag_fault_nth;

unsigned long long procid;

int running;
uint32 completed;
bool collide;
bool is_kernel_64_bit = true;

ALIGNED(64 << 10)
char input_data[kMaxInput];

// Checksum kinds.
const uint64 arg_csum_inet = 0;

// Checksum chunk kinds.
const uint64 arg_csum_chunk_data = 0;
const uint64 arg_csum_chunk_const = 1;

struct thread_t {
	bool created;
	int id;
	osthread_t th;
	char* cover_data;
	char* cover_end;

	event_t ready;
	event_t done;
	uint64* copyout_pos;
	uint64 copyout_index;
	bool colliding;
	bool handled;
	int call_index;
	int call_num;
	int num_args;
	long args[kMaxArgs];
	long res;
	uint32 reserrno;
	uint32 cover_size;
	bool fault_injected;
	int cover_fd;
};

thread_t threads[kMaxThreads];

struct res_t {
	bool executed;
	uint64 val;
};

res_t results[kMaxCommands];

const uint64 kInMagic = 0xbadc0ffeebadface;
const uint32 kOutMagic = 0xbadf00d;

struct handshake_req {
	uint64 magic;
	uint64 flags; // env flags
	uint64 pid;
};

struct handshake_reply {
	uint32 magic;
};

struct execute_req {
	uint64 magic;
	uint64 env_flags;
	uint64 exec_flags;
	uint64 pid;
	uint64 fault_call;
	uint64 fault_nth;
	uint64 prog_size;
};

struct execute_reply {
	uint32 magic;
	uint32 done;
	uint32 status;
};

struct call_reply {
	execute_reply header;
	uint32 call_index;
	uint32 call_num;
	uint32 reserrno;
	uint32 fault_injected;
	uint32 signal_size;
	uint32 cover_size;
	uint32 comps_size;
	// signal/cover/comps follow
};

enum {
	KCOV_CMP_CONST = 1,
	KCOV_CMP_SIZE1 = 0,
	KCOV_CMP_SIZE2 = 2,
	KCOV_CMP_SIZE4 = 4,
	KCOV_CMP_SIZE8 = 6,
	KCOV_CMP_SIZE_MASK = 6,
};

struct kcov_comparison_t {
	// Note: comparisons are always 64-bits regardless of kernel bitness.
	uint64 type;
	uint64 arg1;
	uint64 arg2;
	uint64 pc;

	bool ignore() const;
	void write();
	bool operator==(const struct kcov_comparison_t& other) const;
	bool operator<(const struct kcov_comparison_t& other) const;
};

long execute_syscall(const call_t* c, long a0, long a1, long a2, long a3, long a4, long a5, long a6, long a7, long a8);
thread_t* schedule_call(int call_index, int call_num, bool colliding, uint64 copyout_index, uint64 num_args, uint64* args, uint64* pos);
void handle_completion(thread_t* th);
void execute_call(thread_t* th);
void thread_create(thread_t* th, int id);
void* worker_thread(void* arg);
uint32* write_output(uint32 v);
void write_completed(uint32 completed);
uint64 read_input(uint64** input_posp, bool peek = false);
uint64 read_arg(uint64** input_posp);
uint64 read_const_arg(uint64** input_posp, uint64* size_p, uint64* bf, uint64* bf_off_p, uint64* bf_len_p);
uint64 read_result(uint64** input_posp);
void copyin(char* addr, uint64 val, uint64 size, uint64 bf, uint64 bf_off, uint64 bf_len);
bool copyout(char* addr, uint64 size, uint64* res);
void cover_open();
void cover_enable(thread_t* th);
void cover_reset(thread_t* th);
uint32 cover_read_size(thread_t* th);
bool cover_check(uint32 pc);
bool cover_check(uint64 pc);
static uint32 hash(uint32 a);
static bool dedup(uint32 sig);
void setup_control_pipes();
void receive_handshake();
void receive_execute();

void main_init()
{
	setup_control_pipes();
	if (SYZ_EXECUTOR_USES_FORK_SERVER)
		receive_handshake();
	else
		receive_execute();
	if (flag_cover)
		cover_open();
}

void setup_control_pipes()
{
	if (dup2(0, kInPipeFd) < 0)
		fail("dup2(0, kInPipeFd) failed");
	if (dup2(1, kOutPipeFd) < 0)
		fail("dup2(1, kOutPipeFd) failed");
	if (dup2(2, 1) < 0)
		fail("dup2(2, 1) failed");
	// We used to close(0), but now we dup stderr to stdin to keep fd numbers
	// stable across executor and C programs generated by pkg/csource.
	if (dup2(2, 0) < 0)
		fail("dup2(2, 0) failed");
}

void parse_env_flags(uint64 flags)
{
	flag_debug = flags & (1 << 0);
	flag_cover = flags & (1 << 1);
	flag_sandbox = sandbox_none;
	if (flags & (1 << 2))
		flag_sandbox = sandbox_setuid;
	else if (flags & (1 << 3))
		flag_sandbox = sandbox_namespace;
	flag_enable_tun = flags & (1 << 4);
	flag_enable_net_dev = flags & (1 << 5);
	flag_enable_fault_injection = flags & (1 << 6);
}

void receive_handshake()
{
	handshake_req req = {};
	int n = read(kInPipeFd, &req, sizeof(req));
	if (n != sizeof(req))
		fail("handshake read failed: %d", n);
	if (req.magic != kInMagic)
		fail("bad handshake magic 0x%llx", req.magic);
	parse_env_flags(req.flags);
	procid = req.pid;
}

void reply_handshake()
{
	handshake_reply reply = {};
	reply.magic = kOutMagic;
	if (write(kOutPipeFd, &reply, sizeof(reply)) != sizeof(reply))
		fail("control pipe write failed");
}

void receive_execute()
{
	execute_req req;
	if (read(kInPipeFd, &req, sizeof(req)) != (ssize_t)sizeof(req))
		fail("control pipe read failed");
	if (req.magic != kInMagic)
		fail("bad execute request magic 0x%llx", req.magic);
	if (req.prog_size > kMaxInput)
		fail("bad execute prog size 0x%llx", req.prog_size);
	parse_env_flags(req.env_flags);
	procid = req.pid;
	flag_collect_cover = req.exec_flags & (1 << 0);
	flag_dedup_cover = req.exec_flags & (1 << 1);
	flag_inject_fault = req.exec_flags & (1 << 2);
	flag_collect_comps = req.exec_flags & (1 << 3);
	flag_threaded = req.exec_flags & (1 << 4);
	flag_collide = req.exec_flags & (1 << 5);
	flag_fault_call = req.fault_call;
	flag_fault_nth = req.fault_nth;
	if (!flag_threaded)
		flag_collide = false;
	debug("exec opts: pid=%llu threaded=%d collide=%d cover=%d comps=%d dedup=%d fault=%d/%d/%d prog=%llu\n",
	      procid, flag_threaded, flag_collide, flag_collect_cover, flag_collect_comps,
	      flag_dedup_cover, flag_inject_fault, flag_fault_call, flag_fault_nth,
	      req.prog_size);
	if (SYZ_EXECUTOR_USES_SHMEM) {
		if (req.prog_size)
			fail("need_prog: no program");
		return;
	}
	if (req.prog_size == 0)
		fail("need_prog: no program");
	uint64 pos = 0;
	for (;;) {
		ssize_t rv = read(kInPipeFd, input_data + pos, sizeof(input_data) - pos);
		if (rv < 0)
			fail("read failed");
		pos += rv;
		if (rv == 0 || pos >= req.prog_size)
			break;
	}
	if (pos != req.prog_size)
		fail("bad input size %lld, want %lld", pos, req.prog_size);
}

void reply_execute(int status)
{
	execute_reply reply = {};
	reply.magic = kOutMagic;
	reply.done = true;
	reply.status = status;
	if (write(kOutPipeFd, &reply, sizeof(reply)) != sizeof(reply))
		fail("control pipe write failed");
}

// execute_one executes program stored in input_data.
void execute_one()
{
	// Duplicate global collide variable on stack.
	// Fuzzer once come up with ioctl(fd, FIONREAD, 0x920000),
	// where 0x920000 was exactly collide address, so every iteration reset collide to 0.
	bool colliding = false;
	write_output(0); // Number of executed syscalls (updated later).
	uint64 start = current_time_ms();

retry:
	uint64* input_pos = (uint64*)input_data;

	if (flag_cover && !colliding && !flag_threaded)
		cover_enable(&threads[0]);

	int call_index = 0;
	for (;;) {
		uint64 call_num = read_input(&input_pos);
		if (call_num == instr_eof)
			break;
		if (call_num == instr_copyin) {
			char* addr = (char*)read_input(&input_pos);
			uint64 typ = read_input(&input_pos);
			switch (typ) {
			case arg_const: {
				uint64 size, bf, bf_off, bf_len;
				uint64 arg = read_const_arg(&input_pos, &size, &bf, &bf_off, &bf_len);
				copyin(addr, arg, size, bf, bf_off, bf_len);
				break;
			}
			case arg_result: {
				uint64 meta = read_input(&input_pos);
				uint64 size = meta & 0xff;
				uint64 bf = meta >> 8;
				uint64 val = read_result(&input_pos);
				copyin(addr, val, size, bf, 0, 0);
				break;
			}
			case arg_data: {
				uint64 size = read_input(&input_pos);
				NONFAILING(memcpy(addr, input_pos, size));
				// Read out the data.
				for (uint64 i = 0; i < (size + 7) / 8; i++)
					read_input(&input_pos);
				break;
			}
			case arg_csum: {
				debug("checksum found at %p\n", addr);
				uint64 size = read_input(&input_pos);
				char* csum_addr = addr;
				uint64 csum_kind = read_input(&input_pos);
				switch (csum_kind) {
				case arg_csum_inet: {
					if (size != 2)
						fail("inet checksum must be 2 bytes, not %llu", size);
					debug("calculating checksum for %p\n", csum_addr);
					struct csum_inet csum;
					csum_inet_init(&csum);
					uint64 chunks_num = read_input(&input_pos);
					uint64 chunk;
					for (chunk = 0; chunk < chunks_num; chunk++) {
						uint64 chunk_kind = read_input(&input_pos);
						uint64 chunk_value = read_input(&input_pos);
						uint64 chunk_size = read_input(&input_pos);
						switch (chunk_kind) {
						case arg_csum_chunk_data:
							debug("#%lld: data chunk, addr: %llx, size: %llu\n", chunk, chunk_value, chunk_size);
							NONFAILING(csum_inet_update(&csum, (const uint8*)chunk_value, chunk_size));
							break;
						case arg_csum_chunk_const:
							if (chunk_size != 2 && chunk_size != 4 && chunk_size != 8) {
								fail("bad checksum const chunk size %lld\n", chunk_size);
							}
							// Here we assume that const values come to us big endian.
							debug("#%lld: const chunk, value: %llx, size: %llu\n", chunk, chunk_value, chunk_size);
							csum_inet_update(&csum, (const uint8*)&chunk_value, chunk_size);
							break;
						default:
							fail("bad checksum chunk kind %llu", chunk_kind);
						}
					}
					uint16 csum_value = csum_inet_digest(&csum);
					debug("writing inet checksum %hx to %p\n", csum_value, csum_addr);
					copyin(csum_addr, csum_value, 2, binary_format_native, 0, 0);
					break;
				}
				default:
					fail("bad checksum kind %llu", csum_kind);
				}
				break;
			}
			default:
				fail("bad argument type %llu", typ);
			}
			continue;
		}
		if (call_num == instr_copyout) {
			read_input(&input_pos); // index
			read_input(&input_pos); // addr
			read_input(&input_pos); // size
			// The copyout will happen when/if the call completes.
			continue;
		}

		// Normal syscall.
		if (call_num >= SYZ_SYSCALL_COUNT)
			fail("invalid command number %llu", call_num);
		uint64 copyout_index = read_input(&input_pos);
		uint64 num_args = read_input(&input_pos);
		if (num_args > kMaxArgs)
			fail("command has bad number of arguments %llu", num_args);
		uint64 args[kMaxArgs] = {};
		for (uint64 i = 0; i < num_args; i++)
			args[i] = read_arg(&input_pos);
		for (uint64 i = num_args; i < 6; i++)
			args[i] = 0;
		thread_t* th = schedule_call(call_index++, call_num, colliding, copyout_index, num_args, args, input_pos);

		if (colliding && (call_index % 2) == 0) {
			// Don't wait for every other call.
			// We already have results from the previous execution.
		} else if (flag_threaded) {
			// Wait for call completion.
			// Note: sys knows about this 25ms timeout when it generates
			// timespec/timeval values.
			const uint64 timeout_ms = flag_debug ? 3000 : 25;
			if (event_timedwait(&th->done, timeout_ms))
				handle_completion(th);
			// Check if any of previous calls have completed.
			// Give them some additional time, because they could have been
			// just unblocked by the current call.
			if (running < 0)
				fail("running = %d", running);
			if (running > 0) {
				bool last = read_input(&input_pos, true) == instr_eof;
				uint64 wait = last ? 100 : 2;
				uint64 wait_start = current_time_ms();
				uint64 wait_end = wait_start + wait;
				if (!colliding && wait_end < start + 800)
					wait_end = start + 800;
				while (running > 0 && current_time_ms() <= wait_end) {
					sleep_ms(1);
					for (int i = 0; i < kMaxThreads; i++) {
						th = &threads[i];
						if (!th->handled && event_isset(&th->done))
							handle_completion(th);
					}
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

	if (flag_collide && !flag_inject_fault && !colliding && !collide) {
		debug("enabling collider\n");
		collide = colliding = true;
		goto retry;
	}
}

thread_t* schedule_call(int call_index, int call_num, bool colliding, uint64 copyout_index, uint64 num_args, uint64* args, uint64* pos)
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
	th->colliding = colliding;
	th->copyout_pos = pos;
	th->copyout_index = copyout_index;
	event_reset(&th->done);
	th->handled = false;
	th->call_index = call_index;
	th->call_num = call_num;
	th->num_args = num_args;
	for (int i = 0; i < kMaxArgs; i++)
		th->args[i] = args[i];
	event_set(&th->ready);
	running++;
	return th;
}

template <typename cover_t>
void write_coverage_signal(thread_t* th, uint32* signal_count_pos, uint32* cover_count_pos)
{
	// Write out feedback signals.
	// Currently it is code edges computed as xor of two subsequent basic block PCs.
	cover_t* cover_data = ((cover_t*)th->cover_data) + 1;
	uint32 nsig = 0;
	cover_t prev = 0;
	for (uint32 i = 0; i < th->cover_size; i++) {
		cover_t pc = cover_data[i];
		if (!cover_check(pc)) {
			debug("got bad pc: 0x%llx\n", (uint64)pc);
			doexit(0);
		}
		cover_t sig = pc ^ prev;
		prev = hash(pc);
		if (dedup(sig))
			continue;
		write_output(sig);
		nsig++;
	}
	// Write out number of signals.
	*signal_count_pos = nsig;

	if (!flag_collect_cover)
		return;
	// Write out real coverage (basic block PCs).
	uint32 cover_size = th->cover_size;
	if (flag_dedup_cover) {
		cover_t* end = cover_data + cover_size;
		std::sort(cover_data, end);
		cover_size = std::unique(cover_data, end) - cover_data;
	}
	// Truncate PCs to uint32 assuming that they fit into 32-bits.
	// True for x86_64 and arm64 without KASLR.
	for (uint32 i = 0; i < cover_size; i++)
		write_output(cover_data[i]);
	*cover_count_pos = cover_size;
}

void handle_completion(thread_t* th)
{
	debug("completion of call %d [%s] on thread %d\n", th->call_index, syscalls[th->call_num].name, th->id);
	if (event_isset(&th->ready) || !event_isset(&th->done) || th->handled)
		fail("bad thread state in completion: ready=%d done=%d handled=%d",
		     event_isset(&th->ready), event_isset(&th->done), th->handled);
	if (th->res != (long)-1) {
		if (th->copyout_index != no_copyout) {
			if (th->copyout_index >= kMaxCommands)
				fail("result idx %lld overflows kMaxCommands", th->copyout_index);
			results[th->copyout_index].executed = true;
			results[th->copyout_index].val = th->res;
		}
		for (bool done = false; !done;) {
			uint64 instr = read_input(&th->copyout_pos);
			switch (instr) {
			case instr_copyout: {
				uint64 index = read_input(&th->copyout_pos);
				if (index >= kMaxCommands)
					fail("result idx %lld overflows kMaxCommands", index);
				char* addr = (char*)read_input(&th->copyout_pos);
				uint64 size = read_input(&th->copyout_pos);
				uint64 val = 0;
				if (copyout(addr, size, &val)) {
					results[index].executed = true;
					results[index].val = val;
				}
				debug("copyout 0x%llx from %p\n", val, addr);
				break;
			}
			default:
				done = true;
				break;
			}
		}
	}
	if (!collide && !th->colliding) {
		uint32 reserrno = th->res != -1 ? 0 : th->reserrno;
		if (SYZ_EXECUTOR_USES_SHMEM) {
			write_output(th->call_index);
			write_output(th->call_num);
			write_output(reserrno);
			write_output(th->fault_injected);
			uint32* signal_count_pos = write_output(0); // filled in later
			uint32* cover_count_pos = write_output(0); // filled in later
			uint32* comps_count_pos = write_output(0); // filled in later

			if (flag_collect_comps) {
				// Collect only the comparisons
				uint32 ncomps = th->cover_size;
				kcov_comparison_t* start = (kcov_comparison_t*)(th->cover_data + sizeof(uint64));
				kcov_comparison_t* end = start + ncomps;
				if ((char*)end > th->cover_end)
					fail("too many comparisons %u", ncomps);
				std::sort(start, end);
				ncomps = std::unique(start, end) - start;
				uint32 comps_size = 0;
				for (uint32 i = 0; i < ncomps; ++i) {
					if (start[i].ignore())
						continue;
					comps_size++;
					start[i].write();
				}
				// Write out number of comparisons.
				*comps_count_pos = comps_size;
			} else if (flag_cover) {
				if (is_kernel_64_bit)
					write_coverage_signal<uint64>(th, signal_count_pos, cover_count_pos);
				else
					write_coverage_signal<uint32>(th, signal_count_pos, cover_count_pos);
			}
			debug("out #%u: index=%u num=%u errno=%d sig=%u cover=%u comps=%u\n",
			      completed, th->call_index, th->call_num, reserrno,
			      *signal_count_pos, *cover_count_pos, *comps_count_pos);
			completed++;
			write_completed(completed);
		} else {
			call_reply reply;
			reply.header.magic = kOutMagic;
			reply.header.done = 0;
			reply.header.status = 0;
			reply.call_index = th->call_index;
			reply.call_num = th->call_num;
			reply.reserrno = reserrno;
			reply.fault_injected = th->fault_injected;
			reply.signal_size = 0;
			reply.cover_size = 0;
			reply.comps_size = 0;
			if (write(kOutPipeFd, &reply, sizeof(reply)) != sizeof(reply))
				fail("control pipe call write failed");
			debug("out: index=%u num=%u errno=%d\n", th->call_index, th->call_num, reserrno);
		}
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

	if (flag_cover)
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
	const call_t* call = &syscalls[th->call_num];
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

	if (flag_cover)
		cover_reset(th);
	errno = 0;
	th->res = execute_syscall(call, th->args[0], th->args[1], th->args[2],
				  th->args[3], th->args[4], th->args[5],
				  th->args[6], th->args[7], th->args[8]);
	th->reserrno = errno;
	if (th->res == -1 && th->reserrno == 0)
		th->reserrno = EINVAL; // our syz syscalls may misbehave
	if (flag_cover)
		th->cover_size = cover_read_size(th);
	th->fault_injected = false;

	if (flag_inject_fault && th->call_index == flag_fault_call) {
		th->fault_injected = fault_injected(fail_fd);
		debug("fault injected: %d\n", th->fault_injected);
	}

	if (th->res == -1)
		debug("#%d: %s = errno(%d)\n", th->id, call->name, th->reserrno);
	else
		debug("#%d: %s = 0x%lx\n", th->id, call->name, th->res);
	event_set(&th->done);
}

static uint32 hash(uint32 a)
{
	a = (a ^ 61) ^ (a >> 16);
	a = a + (a << 3);
	a = a ^ (a >> 4);
	a = a * 0x27d4eb2d;
	a = a ^ (a >> 15);
	return a;
}

const uint32 dedup_table_size = 8 << 10;
uint32 dedup_table[dedup_table_size];

// Poorman's best-effort hashmap-based deduplication.
// The hashmap is global which means that we deduplicate across different calls.
// This is OK because we are interested only in new signals.
static bool dedup(uint32 sig)
{
	for (uint32 i = 0; i < 4; i++) {
		uint32 pos = (sig + i) % dedup_table_size;
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

void copyin(char* addr, uint64 val, uint64 size, uint64 bf, uint64 bf_off, uint64 bf_len)
{
	if (bf != binary_format_native && (bf_off != 0 || bf_len != 0))
		fail("bitmask for string format %llu/%llu", bf_off, bf_len);
	switch (bf) {
	case binary_format_native:
		NONFAILING(switch (size) {
			case 1:
				STORE_BY_BITMASK(uint8, addr, val, bf_off, bf_len);
				break;
			case 2:
				STORE_BY_BITMASK(uint16, addr, val, bf_off, bf_len);
				break;
			case 4:
				STORE_BY_BITMASK(uint32, addr, val, bf_off, bf_len);
				break;
			case 8:
				STORE_BY_BITMASK(uint64, addr, val, bf_off, bf_len);
				break;
			default:
				fail("copyin: bad argument size %llu", size);
		});
		break;
	case binary_format_strdec:
		if (size != 20)
			fail("bad strdec size %llu", size);
		NONFAILING(sprintf((char*)addr, "%020llu", val));
		break;
	case binary_format_strhex:
		if (size != 18)
			fail("bad strhex size %llu", size);
		NONFAILING(sprintf((char*)addr, "0x%016llx", val));
		break;
	case binary_format_stroct:
		if (size != 23)
			fail("bad stroct size %llu", size);
		NONFAILING(sprintf((char*)addr, "%023llo", val));
		break;
	default:
		fail("unknown binary format %llu", bf);
	}
}

bool copyout(char* addr, uint64 size, uint64* res)
{
	bool ok = false;
	NONFAILING(
	    switch (size) {
		    case 1:
			    *res = *(uint8*)addr;
			    break;
		    case 2:
			    *res = *(uint16*)addr;
			    break;
		    case 4:
			    *res = *(uint32*)addr;
			    break;
		    case 8:
			    *res = *(uint64*)addr;
			    break;
		    default:
			    fail("copyout: bad argument size %llu", size);
	    } __atomic_store_n(&ok, true, __ATOMIC_RELEASE););
	return ok;
}

uint64 read_arg(uint64** input_posp)
{
	uint64 typ = read_input(input_posp);
	switch (typ) {
	case arg_const: {
		uint64 size, bf, bf_off, bf_len;
		uint64 val = read_const_arg(input_posp, &size, &bf, &bf_off, &bf_len);
		if (bf != binary_format_native)
			fail("bad argument binary format %llu", bf);
		if (bf_off != 0 || bf_len != 0)
			fail("bad argument bitfield %llu/%llu", bf_off, bf_len);
		return val;
	}
	case arg_result: {
		uint64 meta = read_input(input_posp);
		uint64 bf = meta >> 8;
		if (bf != binary_format_native)
			fail("bad result argument format %llu", bf);
		return read_result(input_posp);
	}
	default:
		fail("bad argument type %llu", typ);
	}
}

uint64 read_const_arg(uint64** input_posp, uint64* size_p, uint64* bf_p, uint64* bf_off_p, uint64* bf_len_p)
{
	uint64 meta = read_input(input_posp);
	uint64 val = read_input(input_posp);
	*size_p = meta & 0xff;
	uint64 bf = (meta >> 8) & 0xff;
	*bf_off_p = (meta >> 16) & 0xff;
	*bf_len_p = (meta >> 24) & 0xff;
	uint64 pid_stride = meta >> 32;
	val += pid_stride * procid;
	if (bf == binary_format_bigendian) {
		bf = binary_format_native;
		switch (*size_p) {
		case 2:
			val = htobe16(val);
			break;
		case 4:
			val = htobe32(val);
			break;
		case 8:
			val = htobe64(val);
			break;
		default:
			fail("bad big-endian int size %llu", *size_p);
		}
	}
	*bf_p = bf;
	return val;
}

uint64 read_result(uint64** input_posp)
{
	uint64 idx = read_input(input_posp);
	uint64 op_div = read_input(input_posp);
	uint64 op_add = read_input(input_posp);
	uint64 arg = read_input(input_posp);
	if (idx >= kMaxCommands)
		fail("command refers to bad result %lld", idx);
	if (results[idx].executed) {
		arg = results[idx].val;
		if (op_div != 0)
			arg = arg / op_div;
		arg += op_add;
	}
	return arg;
}

uint64 read_input(uint64** input_posp, bool peek)
{
	uint64* input_pos = *input_posp;
	if ((char*)input_pos >= input_data + kMaxInput)
		fail("input command overflows input %p: [%p:%p)", input_pos, input_data, input_data + kMaxInput);
	if (!peek)
		*input_posp = input_pos + 1;
	return *input_pos;
}

void kcov_comparison_t::write()
{
	// Write order: type arg1 arg2 pc.
	write_output((uint32)type);

	// KCOV converts all arguments of size x first to uintx_t and then to
	// uint64. We want to properly extend signed values, e.g we want
	// int8 c = 0xfe to be represented as 0xfffffffffffffffe.
	// Note that uint8 c = 0xfe will be represented the same way.
	// This is ok because during hints processing we will anyways try
	// the value 0x00000000000000fe.
	switch (type & KCOV_CMP_SIZE_MASK) {
	case KCOV_CMP_SIZE1:
		arg1 = (uint64)(long long)(signed char)arg1;
		arg2 = (uint64)(long long)(signed char)arg2;
		break;
	case KCOV_CMP_SIZE2:
		arg1 = (uint64)(long long)(short)arg1;
		arg2 = (uint64)(long long)(short)arg2;
		break;
	case KCOV_CMP_SIZE4:
		arg1 = (uint64)(long long)(int)arg1;
		arg2 = (uint64)(long long)(int)arg2;
		break;
	}
	bool is_size_8 = (type & KCOV_CMP_SIZE_MASK) == KCOV_CMP_SIZE8;
	if (!is_size_8) {
		write_output((uint32)arg1);
		write_output((uint32)arg2);
		return;
	}
	// If we have 64 bits arguments then write them in Little-endian.
	write_output((uint32)(arg1 & 0xFFFFFFFF));
	write_output((uint32)(arg1 >> 32));
	write_output((uint32)(arg2 & 0xFFFFFFFF));
	write_output((uint32)(arg2 >> 32));
}

bool kcov_comparison_t::operator==(const struct kcov_comparison_t& other) const
{
	// We don't check for PC equality now, because it is not used.
	return type == other.type && arg1 == other.arg1 && arg2 == other.arg2;
}

bool kcov_comparison_t::operator<(const struct kcov_comparison_t& other) const
{
	if (type != other.type)
		return type < other.type;
	if (arg1 != other.arg1)
		return arg1 < other.arg1;
	// We don't check for PC equality now, because it is not used.
	return arg2 < other.arg2;
}
