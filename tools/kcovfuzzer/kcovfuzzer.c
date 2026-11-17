// KCOV glue for libfuzzer. Build as:
// clang tools/kcovfuzzer/kcovfuzzer.c -fsanitize=fuzzer -Wall -o fuzzer
// Run as:
// KCOVFUZZER=bpf ./fuzzer -min_len=8 -max_len=129 corpus_bpf
// KCOVFUZZER=bpf KCOV_CMP=1 ./fuzzer -min_len=8 -max_len=129 corpus_bpf
// KCOVFUZZER=trace_filter ./fuzzer -max_len=100 -only_ascii=1 corpus_trace_filter
// KCOVFUZZER=binfmt ./fuzzer -max_len=30 -only_ascii=1 corpus_binfmt

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <linux/kcov.h>
#include <memory.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

struct kcov_comparison_t {
	uint64_t type;
	uint64_t arg1;
	uint64_t arg2;
	uint64_t pc;
};

__attribute__((weak)) void __sanitizer_cov_trace_cmp1(uint8_t, uint8_t);
__attribute__((weak)) void __sanitizer_cov_trace_cmp2(uint16_t, uint16_t);
__attribute__((weak)) void __sanitizer_cov_trace_cmp4(uint32_t, uint32_t);
__attribute__((weak)) void __sanitizer_cov_trace_cmp8(uint64_t, uint64_t);
__attribute__((weak)) void __sanitizer_cov_trace_const_cmp1(uint8_t, uint8_t);
__attribute__((weak)) void __sanitizer_cov_trace_const_cmp2(uint16_t, uint16_t);
__attribute__((weak)) void __sanitizer_cov_trace_const_cmp4(uint32_t, uint32_t);
__attribute__((weak)) void __sanitizer_cov_trace_const_cmp8(uint64_t, uint64_t);
__attribute__((section("__libfuzzer_extra_counters"))) unsigned char libfuzzer_coverage[64 << 10];

static uint64_t* kcov_data;
static int kcov_mode = KCOV_TRACE_PC;

int LLVMFuzzerInitialize(__attribute__((unused)) int* argc, __attribute__((unused)) char*** argv);
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

static void dump_input(const uint8_t* data, size_t size);
static void (*fuzz_func)(const uint8_t*, size_t);
static void fail(const char* msg, ...);
static void cover_start(void);
static void cover_stop(void);

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
	dump_input(data, size);
	fuzz_func(data, size);
	return 0;
}

void bpf(const uint8_t* data, size_t size)
{
	union bpf_attr attr;
	memset(&attr, 0, sizeof(attr));
	attr.map_type = BPF_MAP_TYPE_HASH;
	attr.key_size = 8;
	attr.value_size = 8;
	attr.max_entries = 2;
	int mfd = syscall(SYS_bpf, BPF_MAP_CREATE, &attr, sizeof(attr));

	memset(&attr, 0, sizeof(attr));
	attr.prog_type = BPF_PROG_TYPE_SOCKET_FILTER;
	attr.insns = (uint64_t)data;
	attr.insn_cnt = size / 8;
	attr.license = (uint64_t)"GPL";

	cover_start();
	int pfd = syscall(SYS_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
	if (pfd != -1) {
		memset(&attr, 0, sizeof(attr));
		attr.test.prog_fd = pfd;
		syscall(SYS_bpf, BPF_PROG_TEST_RUN, &attr, sizeof(attr));
	}
	cover_stop();

	if (pfd != -1)
		close(pfd);
	if (mfd != -1)
		close(mfd);
}

void trace_filter(const uint8_t* data, size_t size)
{
	static int fd0 = -1, fd1 = -1, fd2 = -1;
	if (fd0 == -1) {
		fd0 = open("/sys/kernel/debug/tracing/events/syscalls/sys_exit_read/enable", O_RDWR);
		if (fd0 == -1)
			fail("open enable failed");
		fd1 = open("/sys/kernel/debug/tracing/events/syscalls/sys_exit_read/filter", O_RDWR);
		if (fd1 == -1)
			fail("open filter failed");
		fd2 = open("/sys/kernel/debug/tracing/events/syscalls/sys_exit_read/trigger", O_RDWR);
		if (fd2 == -1)
			fail("open trigger failed");
	}

	cover_start();
	char buf[256];
	buf[0] = '1';
	write(fd0, buf, 1);
	write(fd1, data, size);
	read(fd1, buf, sizeof(buf));
	buf[0] = '0';
	write(fd1, buf, 1);
	write(fd2, data, size);
	read(fd2, buf, sizeof(buf));
	buf[0] = '0';
	write(fd0, buf, 1);
	cover_stop();
}

void binfmt(const uint8_t* data, size_t size)
{
	static int fd = -1;
	static int status_fd = -1;
	if (fd == -1) {
		fd = open("/proc/sys/fs/binfmt_misc/register", O_WRONLY);
		if (fd == -1)
			fail("open(/proc/sys/fs/binfmt_misc/register) failed");
		status_fd = open("/proc/sys/fs/binfmt_misc/status", O_WRONLY);
	}

	// Reset previously registered entries so BINFMT_MISC_INTERP_MAX isn't exhausted
	if (status_fd != -1)
		(void)write(status_fd, "-1", 2);

	cover_start();
	write(fd, data, size);
	cover_stop();
}

#define KCOV_COVER_SIZE (256 << 10)

int LLVMFuzzerInitialize(__attribute__((unused)) int* argc, __attribute__((unused)) char*** argv)
{
	const char* name = getenv("KCOVFUZZER");
	if (!name) {
		fail("KCOVFUZZER environment variable is not set.\n"
		     "Usage: KCOVFUZZER={bpf|trace_filter|binfmt} ./fuzzer [flags] [corpus]");
	}

	if (strcmp(name, "bpf") == 0)
		fuzz_func = bpf;
	else if (strcmp(name, "trace_filter") == 0)
		fuzz_func = trace_filter;
	else if (strcmp(name, "binfmt") == 0)
		fuzz_func = binfmt;
	else
		fail("unknown fuzz function '%s' (expected bpf, trace_filter, or binfmt)", name);

	int kcov = open("/sys/kernel/debug/kcov", O_RDWR);
	if (kcov == -1)
		fail("open of /sys/kernel/debug/kcov failed (check CONFIG_KCOV=y and debugfs mount)");
	if (ioctl(kcov, KCOV_INIT_TRACE, KCOV_COVER_SIZE))
		fail("cover init trace write failed");
	kcov_data = (uint64_t*)mmap(NULL, KCOV_COVER_SIZE * sizeof(kcov_data[0]),
				    PROT_READ | PROT_WRITE, MAP_SHARED, kcov, 0);
	if (kcov_data == MAP_FAILED)
		fail("cover mmap failed");

	const char* cmp_env = getenv("KCOV_CMP");
	if (cmp_env && (strcmp(cmp_env, "1") == 0 || strcmp(cmp_env, "true") == 0)) {
		if (ioctl(kcov, KCOV_ENABLE, KCOV_TRACE_CMP) == 0) {
			kcov_mode = KCOV_TRACE_CMP;
			fprintf(stderr, "INFO: KCOV enabled in TRACE_CMP mode\n");
		} else {
			fprintf(stderr, "WARN: KCOV_ENABLE(KCOV_TRACE_CMP) failed, falling back to TRACE_PC\n");
			if (ioctl(kcov, KCOV_ENABLE, KCOV_TRACE_PC))
				fail("cover enable write trace failed");
			kcov_mode = KCOV_TRACE_PC;
		}
	} else {
		if (ioctl(kcov, KCOV_ENABLE, KCOV_TRACE_PC))
			fail("cover enable write trace failed");
		kcov_mode = KCOV_TRACE_PC;
	}
	close(kcov);
	return 0;
}

static inline void record_coverage(uint64_t pc, uint64_t* prev_pc)
{
	uint64_t sig = pc;
	if (*prev_pc) {
		// Directed edge hash (prev_pc -> pc)
		sig ^= ((*prev_pc >> 4) | (*prev_pc << 60));
	}
	*prev_pc = pc;

	// SplitMix64 mixing to prevent instruction alignment / power-of-2 clustering
	sig ^= sig >> 30;
	sig *= 0xbf58476d1ce4e5b9ULL;
	sig ^= sig >> 27;
	sig *= 0x94d049bb133111ebULL;
	sig ^= sig >> 31;

	size_t idx = sig % sizeof(libfuzzer_coverage);
	// Saturating increment to prevent 256 -> 0 counter wrap-around
	if (libfuzzer_coverage[idx] < 255)
		libfuzzer_coverage[idx]++;
}

static inline void forward_comparison(uint64_t type, uint64_t arg1, uint64_t arg2)
{
	bool is_const = (type & KCOV_CMP_CONST);
	uint64_t size_code = (type & KCOV_CMP_MASK);

	switch (size_code) {
	case KCOV_CMP_SIZE(0): // 1 byte (log2(1) = 0)
		if (is_const && __sanitizer_cov_trace_const_cmp1)
			__sanitizer_cov_trace_const_cmp1((uint8_t)arg1, (uint8_t)arg2);
		else if (__sanitizer_cov_trace_cmp1)
			__sanitizer_cov_trace_cmp1((uint8_t)arg1, (uint8_t)arg2);
		break;
	case KCOV_CMP_SIZE(1): // 2 bytes (log2(2) = 1)
		if (is_const && __sanitizer_cov_trace_const_cmp2)
			__sanitizer_cov_trace_const_cmp2((uint16_t)arg1, (uint16_t)arg2);
		else if (__sanitizer_cov_trace_cmp2)
			__sanitizer_cov_trace_cmp2((uint16_t)arg1, (uint16_t)arg2);
		break;
	case KCOV_CMP_SIZE(2): // 4 bytes (log2(4) = 2)
		if (is_const && __sanitizer_cov_trace_const_cmp4)
			__sanitizer_cov_trace_const_cmp4((uint32_t)arg1, (uint32_t)arg2);
		else if (__sanitizer_cov_trace_cmp4)
			__sanitizer_cov_trace_cmp4((uint32_t)arg1, (uint32_t)arg2);
		break;
	case KCOV_CMP_SIZE(3): // 8 bytes (log2(8) = 3)
		if (is_const && __sanitizer_cov_trace_const_cmp8)
			__sanitizer_cov_trace_const_cmp8(arg1, arg2);
		else if (__sanitizer_cov_trace_cmp8)
			__sanitizer_cov_trace_cmp8(arg1, arg2);
		break;
	}
}

void cover_start(void)
{
	__atomic_store_n(&kcov_data[0], 0, __ATOMIC_RELAXED);
}

void cover_stop(void)
{
	uint64_t nrecords = __atomic_load_n(&kcov_data[0], __ATOMIC_RELAXED);
	uint64_t prev_pc = 0;

	if (kcov_mode == KCOV_TRACE_CMP) {
		uint64_t max_comps = (KCOV_COVER_SIZE - 1) / 4;
		if (nrecords > max_comps)
			nrecords = max_comps;

		struct kcov_comparison_t* cmps = (struct kcov_comparison_t*)&kcov_data[1];
		for (uint64_t i = 0; i < nrecords; i++) {
			record_coverage(cmps[i].pc, &prev_pc);
			forward_comparison(cmps[i].type, cmps[i].arg1, cmps[i].arg2);
		}
	} else {
		if (nrecords >= KCOV_COVER_SIZE)
			nrecords = KCOV_COVER_SIZE - 1;

		for (uint64_t i = 0; i < nrecords; i++) {
			uint64_t pc = __atomic_load_n(&kcov_data[i + 1], __ATOMIC_RELAXED);
			record_coverage(pc, &prev_pc);
		}
	}
}

void dump_input(const uint8_t* data, size_t size)
{
	static int kmsg = -1;
	if (kmsg == -1) {
		kmsg = open("/dev/kmsg", O_WRONLY);
		if (kmsg == -1)
			fail("open(/dev/kmsg) failed");
		int printk_devkmsg = open("/proc/sys/kernel/printk_devkmsg", O_WRONLY);
		if (printk_devkmsg == -1)
			fail("open(/proc/sys/kernel/printk_devkmsg) failed");
		if (write(printk_devkmsg, "on", 3) != 3)
			fail("write(/proc/sys/kernel/printk_devkmsg) failed");
		close(printk_devkmsg);
	}

	char buf[1024];
	int prefix_len = snprintf(buf, sizeof(buf), "INPUT[%zu]: ", size);
	if (prefix_len < 0 || prefix_len >= (int)sizeof(buf) - 10)
		return;

	char* pos = buf + prefix_len;
	for (size_t i = 0; i < size; i++) {
		if (pos > buf + sizeof(buf) - 10) {
			*pos++ = '.';
			*pos++ = '.';
			*pos++ = '.';
			break;
		}
		unsigned char ch = data[i];
		if (ch >= 0x20 && ch < 0x7f && ch != '\\') {
			*pos++ = ch;
			continue;
		}
		*pos++ = '\\';
		*pos++ = 'x';
		unsigned char hi = ch >> 4;
		*pos++ = (hi <= 9) ? ('0' + hi) : ('a' + hi - 10);
		unsigned char lo = ch & 0xf;
		*pos++ = (lo <= 9) ? ('0' + lo) : ('a' + lo - 10);
	}
	*pos++ = '\n';
	if (write(kmsg, buf, pos - buf) != pos - buf)
		fail("write(/dev/kmsg) failed");
}

void fail(const char* msg, ...)
{
	int e = errno;
	va_list args;
	va_start(args, msg);
	vfprintf(stderr, msg, args);
	va_end(args);
	fprintf(stderr, " (errno %d)\n", e);
	_exit(1);
}
