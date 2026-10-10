// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// IMPORTANT: Do not copy the macros or definitions below directly into your reproducer.
// Instead, add the following line to your reproducer:
// #include "race_toolkit.h"

// --- Race Condition Toolkit ---
// Macros and snippets for CPU pinning, memory barriers, and userfaultfd.

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <linux/futex.h>
#include <linux/hw_breakpoint.h>
#include <linux/perf_event.h>
#include <linux/userfaultfd.h>
#include <poll.h>
#include <pthread.h>
#include <sched.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

// Unbuffered I/O: Ensure logs are written immediately.
#define SETUP_UNBUFFERED_IO() setvbuf(stdout, NULL, _IONBF, 0)

// CPU Pinning: Pin the current thread to a specific CPU core.
#define PIN_TO_CPU(cpu)                                                \
	do {                                                           \
		cpu_set_t mask;                                        \
		CPU_ZERO(&mask);                                       \
		CPU_SET(cpu, &mask);                                   \
		if (sched_setaffinity(0, sizeof(mask), &mask) == -1) { \
			perror("sched_setaffinity");                   \
		}                                                      \
	} while (0)

// Memory Barrier: Ensure memory ordering.
#define MB() __atomic_thread_fence(__ATOMIC_SEQ_CST)

// Spin-wait Barrier: Wait until a memory location has a specific value.
// Best for tight race windows (low latency, no context switches).
#define WAIT_ON(addr, val)                                               \
	do {                                                             \
		while (__atomic_load_n(addr, __ATOMIC_ACQUIRE) != (val)) \
			;                                                \
	} while (0)

// Signal: Set a memory location to a specific value to release a WAIT_ON.
#define SIGNAL(addr, val) __atomic_store_n(addr, val, __ATOMIC_RELEASE)

// --- Timing Primitives ---
// Robust timing loops in VM environments (using CLOCK_MONOTONIC to avoid time(NULL) jumps).

static inline double timer_elapsed_sec(struct timespec* start)
{
	struct timespec now;
	if (clock_gettime(CLOCK_MONOTONIC, &now) == -1) {
		perror("clock_gettime(CLOCK_MONOTONIC) elapsed");
		exit(1);
	}
	return (double)(now.tv_sec - start->tv_sec) + (double)(now.tv_nsec - start->tv_nsec) / 1e9;
}

// Initialize a monotonic timer variable.
#define TIMER_START(t)                                          \
	struct timespec t;                                      \
	if (clock_gettime(CLOCK_MONOTONIC, &t) == -1) {         \
		perror("clock_gettime(CLOCK_MONOTONIC) start"); \
		exit(1);                                        \
	}

// Check if the elapsed time since 't' is less than 'sec' seconds.
#define TIMER_NOT_EXPIRED(t, sec) (timer_elapsed_sec(&(t)) < (double)(sec))

// Futex-based Event: Shared with syzkaller executor.
// Best for general synchronization or longer waits to save CPU.
typedef struct {
	int state;
} event_t;

static void event_init(event_t* ev)
{
	ev->state = 0;
}
static void event_reset(event_t* ev)
{
	ev->state = 0;
}

static void event_set(event_t* ev)
{
	if (__atomic_load_n(&ev->state, __ATOMIC_ACQUIRE)) {
		fprintf(stderr, "event already set\n");
		exit(1);
	}
	__atomic_store_n(&ev->state, 1, __ATOMIC_RELEASE);
	syscall(SYS_futex, &ev->state, FUTEX_WAKE | FUTEX_PRIVATE_FLAG, 1000000);
}

static void event_wait(event_t* ev)
{
	while (!__atomic_load_n(&ev->state, __ATOMIC_ACQUIRE))
		syscall(SYS_futex, &ev->state, FUTEX_WAIT | FUTEX_PRIVATE_FLAG, 0, 0);
}

// userfaultfd setup: Register a memory range for page fault handling.
static int setup_uffd(void* addr, size_t len)
{
	int uffd = syscall(__NR_userfaultfd, O_CLOEXEC | O_NONBLOCK);
	if (uffd == -1)
		return -1;
	struct uffdio_api api = {.api = UFFD_API, .features = 0};
	if (ioctl(uffd, UFFDIO_API, &api) == -1) {
		close(uffd);
		return -1;
	}
	struct uffdio_register reg = {
	    .range = {.start = (uintptr_t)addr, .len = len},
	    .mode = UFFDIO_REGISTER_MODE_MISSING};
	if (ioctl(uffd, UFFDIO_REGISTER, &reg) == -1) {
		close(uffd);
		return -1;
	}
	return uffd;
}

// Lookup a kernel symbol (optionally "sym+0xoffset") via /proc/kallsyms.
static inline uintptr_t kallsyms_lookup(const char* spec)
{
	size_t n = strcspn(spec, "+");
	char sym[128];
	if (n == 0 || n >= sizeof(sym))
		return 0;
	memcpy(sym, spec, n);
	sym[n] = '\0';
	unsigned long offset = spec[n] == '+' ? strtoul(spec + n + 1, NULL, 0) : 0;
	FILE* f = fopen("/proc/kallsyms", "r");
	if (!f)
		return 0;
	uintptr_t addr = 0;
	char line[256];
	while (fgets(line, sizeof(line), f)) {
		unsigned long a;
		char type, name[128];
		if (sscanf(line, "%lx %c %127s", &a, &type, name) == 3 && a != 0 && strcmp(name, sym) == 0) {
			addr = (uintptr_t)a + offset;
			break;
		}
	}
	fclose(f);
	return addr;
}

// Hardware breakpoint delay injector: opens a PERF_TYPE_BREAKPOINT on (pid, addr) and
// attaches a bounded BPF_PROG_TYPE_PERF_EVENT loop that stalls inside the #DB handler for
// delay_us microseconds (capped by the 32768-iteration loop bound, ~1-3 ms per hit in VMs).
// Returns the perf_event fd (close it to detach), or -1 on error.
// Call with pid=0 in main() before pthread_create() so all threads inherit the breakpoint.
// Note: HW_BREAKPOINT_RW / HW_BREAKPOINT_W work on kernel data addresses even when
// CONFIG_KPROBES=n; HW_BREAKPOINT_X requires CONFIG_KPROBES=y for kernel text addresses.
static inline int setup_delay_bp(pid_t pid, uintptr_t addr, uint32_t bp_type, uint64_t bp_len, uint32_t delay_us)
{
	struct perf_event_attr pe = {
	    .type = PERF_TYPE_BREAKPOINT,
	    .size = sizeof(pe),
	    .bp_type = bp_type,
	    .bp_addr = addr,
	    .bp_len = (bp_type == HW_BREAKPOINT_X) ? sizeof(long) : bp_len,
	    .sample_period = 1,
	    .disabled = 1,
	    .inherit = 1,
	    .inherit_thread = 1,
	    .remove_on_exec = 1,
	};
	int pfd = syscall(__NR_perf_event_open, &pe, pid, -1, -1, PERF_FLAG_FD_CLOEXEC);
	if (pfd == -1)
		return -1;

	struct bpf_insn insns[] = {
	    // R0 = bpf_ktime_get_ns(); R6 = R0; R7 = 32768 (bounded loop limit);
	    // zero-extend uint32_t delay_us via 32-bit MOV then multiply by 1000 to avoid signed .imm overflow.
	    {.code = BPF_JMP | BPF_CALL, .imm = BPF_FUNC_ktime_get_ns},
	    {.code = BPF_ALU64 | BPF_MOV | BPF_X, .dst_reg = BPF_REG_6, .src_reg = BPF_REG_0},
	    {.code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = BPF_REG_7, .imm = 32768},
	    {.code = BPF_ALU | BPF_MOV | BPF_K, .dst_reg = BPF_REG_8, .imm = (int32_t)delay_us},
	    {.code = BPF_ALU64 | BPF_MUL | BPF_K, .dst_reg = BPF_REG_8, .imm = 1000},
	    // loop: if (R7 == 0) goto exit (+4); R7 -= 1;
	    {.code = BPF_JMP | BPF_JEQ | BPF_K, .dst_reg = BPF_REG_7, .off = 4, .imm = 0},
	    {.code = BPF_ALU64 | BPF_SUB | BPF_K, .dst_reg = BPF_REG_7, .imm = 1},
	    // R0 = bpf_ktime_get_ns() - R6; if (R0 < R8) goto loop (-5);
	    {.code = BPF_JMP | BPF_CALL, .imm = BPF_FUNC_ktime_get_ns},
	    {.code = BPF_ALU64 | BPF_SUB | BPF_X, .dst_reg = BPF_REG_0, .src_reg = BPF_REG_6},
	    {.code = BPF_JMP | BPF_JLT | BPF_X, .dst_reg = BPF_REG_0, .src_reg = BPF_REG_8, .off = -5},
	    // exit: R0 = 0; exit
	    {.code = BPF_ALU64 | BPF_MOV | BPF_K, .dst_reg = BPF_REG_0, .imm = 0},
	    {.code = BPF_JMP | BPF_EXIT},
	};
	union bpf_attr attr = {
	    .prog_type = BPF_PROG_TYPE_PERF_EVENT,
	    .insn_cnt = sizeof(insns) / sizeof(insns[0]),
	    .insns = (uintptr_t)insns,
	    .license = (uintptr_t)"GPL",
	};
	int bfd = syscall(__NR_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
	if (bfd == -1) {
		close(pfd);
		return -1;
	}
	int ok = ioctl(pfd, PERF_EVENT_IOC_SET_BPF, bfd) == 0 &&
		 ioctl(pfd, PERF_EVENT_IOC_ENABLE, 0) == 0;
	close(bfd);
	if (!ok) {
		close(pfd);
		return -1;
	}
	return pfd;
}

// --- Guidance on Usage ---
// 1. Use WAIT_ON/SIGNAL for tight race conditions to avoid scheduling overhead.
// 2. Use event_t (futexes) for general coordination or when waiting for longer periods.
// 3. Always use PIN_TO_CPU to increase race probability on multi-core systems.
// 4. Use setup_uffd to register a memory range for page fault handling, or setup_delay_bp
//    (with kallsyms_lookup) to inject targeted hardware-breakpoint delays on kernel accesses.
// 5. Call SETUP_UNBUFFERED_IO() at the start of main() to ensure that logs are printed
//    immediately. This is essential for understanding the exact interleaving of events
//    when debugging race conditions.
// 6. For timing-based loops (e.g., running a race for 10 seconds), do NOT use time(NULL)
//    or loops relying on real-time clocks, as VM clocks are highly unreliable and can fail or drift.
//    Instead, use the robust monotonic timing primitives TIMER_START and TIMER_NOT_EXPIRED:
//        TIMER_START(start);
//        while (TIMER_NOT_EXPIRED(start, 10.0)) {
//            // Your race logic here
//        }
