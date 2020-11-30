// KCOV glue for libfuzzer. Build as:
// clang tools/kcovfuzzer/kcovfuzzer.c -fsanitize=fuzzer -static -Wall -o fuzzer
// Run as:
//
// KCOVFUZZER=bpf ./fuzzer -max_len=129 corpus_bpf
// KCOVFUZZER=trace_filter ./fuzzer -max_len=100 -only_ascii=1 corpus_trace_filter
// KCOVFUZZER=binfmt ./fuzzer -max_len=30 -only_ascii=1 corpus_binfmt
//
// If you build with -static, then the following env needs to be exported:
// UBSAN_OPTIONS="handle_segv=0 handle_sigbus=0 handle_abort=0 handle_sigill=0 handle_sigtrap=0 handle_sigfpe=0"
// and the following flags added to fuzzer invocation:
// -timeout=0 -rss_limit_mb=0 -handle_segv=0 -handle_bus=0 -handle_abrt=0 -handle_ill=0 \
// -handle_fpe=0 -handle_int=0 -handle_term=0 -handle_xfsz=0 -handle_usr1=0 -handle_usr2=0

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <linux/bpf.h>
#include <memory.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <unistd.h>

void init(const char*, long);
void dump_input(const char*, long);
void (*fuzz_func)(const char*, long) = init;
void fail(const char* msg, ...);
void cover_start();
void cover_stop();

int LLVMFuzzerTestOneInput(const char* data, long size)
{
	dump_input(data, size);
	fuzz_func(data, size);
	return 0;
}

void bpf(const char* data, long size)
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
	attr.license = (uint64_t) "GPL";

	cover_start();
	int pfd = syscall(SYS_bpf, BPF_PROG_LOAD, &attr, sizeof(attr));
	if (pfd != -1) {
		memset(&attr, 0, sizeof(attr));
		attr.test.prog_fd = pfd;
		syscall(SYS_bpf, BPF_PROG_TEST_RUN, &attr, sizeof(attr));
	}
	cover_stop();
	close(pfd);
	close(mfd);
}

void trace_filter(const char* data, long size)
{
	int fd0 = open("/sys/kernel/debug/tracing/events/syscalls/sys_exit_read/enable", O_RDWR);
	if (fd0 == -1)
		fail("open enable failed");
	int fd1 = open("/sys/kernel/debug/tracing/events/syscalls/sys_exit_read/filter", O_RDWR);
	if (fd1 == -1)
		fail("open filter failed");
	int fd2 = open("/sys/kernel/debug/tracing/events/syscalls/sys_exit_read/trigger", O_RDWR);
	if (fd2 == -1)
		fail("open trigger failed");
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
	close(fd0);
	close(fd1);
	close(fd2);
}

void binfmt(const char* data, long size)
{
	static int fd = -1;
	if (fd == -1)
		fd = open("/proc/sys/fs/binfmt_misc/register", O_WRONLY);
	if (fd == -1)
		fail("open(/proc/sys/fs/binfmt_misc/register) failed");
	cover_start();
	write(fd, data, size);
	cover_stop();
}

#define KCOV_COVER_SIZE (256 << 10)
#define KCOV_TRACE_PC 0
#define KCOV_INIT_TRACE64 _IOR('c', 1, uint64_t)
#define KCOV_ENABLE _IO('c', 100)

__attribute__((section("__libfuzzer_extra_counters"))) unsigned char libfuzzer_coverage[32 << 10];
uint64_t* kcov_data;

void init(const char* data, long size)
{
	const char* name = getenv("KCOVFUZZER");
	if (strcmp(name, "bpf") == 0)
		fuzz_func = bpf;
	else if (strcmp(name, "trace_filter") == 0)
		fuzz_func = trace_filter;
	else if (strcmp(name, "binfmt") == 0)
		fuzz_func = binfmt;
	else
		fail("unknown fuzz function '%s'", name);

	int kcov = open("/sys/kernel/debug/kcov", O_RDWR);
	if (kcov == -1)
		fail("open of /sys/kernel/debug/kcov failed");
	if (ioctl(kcov, KCOV_INIT_TRACE64, KCOV_COVER_SIZE))
		fail("cover init trace write failed");
	kcov_data = (uint64_t*)mmap(NULL, KCOV_COVER_SIZE * sizeof(kcov_data[0]),
				    PROT_READ | PROT_WRITE, MAP_SHARED, kcov, 0);
	if (kcov_data == MAP_FAILED)
		fail("cover mmap failed");
	if (ioctl(kcov, KCOV_ENABLE, KCOV_TRACE_PC))
		fail("cover enable write trace failed");
	close(kcov);

	fuzz_func(data, size);
}

void cover_start()
{
	__atomic_store_n(&kcov_data[0], 0, __ATOMIC_RELAXED);
}

void cover_stop()
{
	uint64_t ncov = __atomic_load_n(&kcov_data[0], __ATOMIC_RELAXED);
	if (ncov >= KCOV_COVER_SIZE)
		fail("too much cover: %llu", ncov);
	for (uint64_t i = 0; i < ncov; i++) {
		uint64_t pc = __atomic_load_n(&kcov_data[i + 1], __ATOMIC_RELAXED);
		libfuzzer_coverage[pc % sizeof(libfuzzer_coverage)]++;
	}
}

void dump_input(const char* data, long size)
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
	char* pos = buf + sprintf(buf, "INPUT[%ld]: ", size);
	for (long i = 0; i < size; i++) {
		if (pos > buf + sizeof(buf) - 10) {
			*pos++ = '.';
			*pos++ = '.';
			*pos++ = '.';
			break;
		}
		char ch = data[i];
		if (ch >= 0x20 && ch < 0x7f && ch != '\\') {
			*pos++ = ch;
			continue;
		}
		*pos++ = '\\';
		*pos++ = 'x';
		char hi = ch >> 4;
		if (hi <= 9)
			*pos++ = '0' + hi;
		else
			*pos++ = 'a' + hi - 9;
		char lo = ch & 0xf;
		if (lo <= 9)
			*pos++ = '0' + lo;
		else
			*pos++ = 'a' + lo - 9;
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
