// Copyright 2019 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// fops_probe utility helps to understand what file_operations callbacks
// are attached to a particular file. Requries KCOV and KALLSYMS.
// Build with:
//	g++ tools/fops_probe/fops_probe.cc -Wall -static -o fops_probe
// Then copy the binary to target machine and run as:
//	./fops_probe /dev/fb0
// You should see output similar to:
//
//	ffffffff81bcccb9 vfs_read
//	................
//	ffffffff83af85c3 fb_read
//	ffffffff83b52af5 cirrusfb_sync
//
//	ffffffff81bcd219 vfs_write
//	................
//	ffffffff83af7fe2 fb_write
//	ffffffff83b52af5 cirrusfb_sync
//
//	ffffffff81c1b745 do_vfs_ioctl
//	ffffffff83af7ea9 fb_ioctl
//
//	ffffffff81a4ea44 do_mmap
//	................
//	ffffffff83af716c fb_mmap
//
// which allows to understand what callbacks are associated with /dev/fb0.

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <linux/kcov.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <functional>
#include <map>
#include <set>
#include <string>

#define COVER_SIZE (1 << 20)

typedef std::map<long long, std::string> kallsyms_map_t;

static __attribute__((noreturn)) __attribute__((format(printf, 1, 2))) void failf(const char* msg, ...);
static kallsyms_map_t read_kallsyms();
static bool should_skip(const std::string& sym);
static void probe_callback(uint64_t* cover, const kallsyms_map_t& kallsyms,
			   const std::string& start_sym, std::function<void(void)> fn);

int main(int argc, char** argv)
{
	if (argc != 2)
		failf("usage: fops_probe file");
	int fd = open(argv[1], O_RDWR);
	if (fd == -1) {
		fd = open(argv[1], O_RDONLY);
		if (fd == -1)
			failf("failed to open %s", argv[1]);
	}
	const kallsyms_map_t kallsyms = read_kallsyms();
	int kcov = open("/sys/kernel/debug/kcov", O_RDWR);
	if (kcov == -1)
		failf("failed to open /sys/kernel/debug/kcov");
	if (ioctl(kcov, KCOV_INIT_TRACE, COVER_SIZE))
		failf("KCOV_INIT_TRACE failed");
	uint64_t* cover = (uint64_t*)mmap(NULL, COVER_SIZE * 8, PROT_READ | PROT_WRITE, MAP_SHARED, kcov, 0);
	if (cover == MAP_FAILED)
		failf("cover mmap failed");
	if (ioctl(kcov, KCOV_ENABLE, KCOV_TRACE_PC))
		failf("KCOV_ENABLE failed");
	probe_callback(cover, kallsyms, "do_vfs_ioctl", [&]() { ioctl(fd, 0, 0); });
	probe_callback(cover, kallsyms, "do_mmap", [&]() { mmap(0, 4096, PROT_READ, MAP_PRIVATE, fd, 0); });
	probe_callback(cover, kallsyms, "vfs_write", [&]() { write(fd, 0, 0); });
	probe_callback(cover, kallsyms, "vfs_read", [&]() { read(fd, 0, 0); });
	return 0;
}

void probe_callback(uint64_t* cover, const kallsyms_map_t& kallsyms,
		    const std::string& start_sym, std::function<void(void)> fn)
{
	__atomic_store_n(&cover[0], 0, __ATOMIC_SEQ_CST);
	fn();
	uint64_t ncover = __atomic_load_n(&cover[0], __ATOMIC_SEQ_CST);
	bool started = false;
	std::set<std::string> seen;
	for (uint64_t i = 0; i < ncover; i++) {
		long long pc = cover[i + 1];
		auto it = kallsyms.lower_bound(pc - 1);
		const std::string& sym = it == kallsyms.begin() ? "" : (--it)->second;
		if (!started && sym != start_sym)
			continue;
		started = true;
		if (!seen.insert(sym).second || should_skip(sym))
			continue;
		printf("%0llx %s\n", pc, sym.c_str());
	}
	printf("\n");
}

bool should_skip(const std::string& sym)
{
	static const char* skip[] = {
	    "security",
	    "tomoyo",
	    "selinux",
	    "apparmor",
	    "smack",
	    "policy",
	    "stack_trace",
	    "should_fail",
	    "debug",
	    "trace",
	    "snprintf",
	    "vsnprintf",
	};
	for (size_t i = 0; i < sizeof(skip) / sizeof(skip[0]); i++) {
		if (!strncmp(sym.c_str(), skip[i], strlen(skip[i])))
			return true;
	}
	return false;
}

kallsyms_map_t read_kallsyms()
{
	kallsyms_map_t kallsyms;
	FILE* f = fopen("/proc/kallsyms", "r");
	if (f == NULL)
		failf("failed to open /proc/kallsyms");
	size_t n = 0;
	char* line = NULL;
	for (;;) {
		ssize_t len = getline(&line, &n, f);
		if (len < 0)
			break;
		long long pc;
		char typ;
		char sym[1024];
		if (sscanf(line, "%016llx %c %s\n", &pc, &typ, sym) != 3)
			failf("bad line in kallsyms: %s", line);
		if (typ != 't' && typ != 'T')
			continue;
		kallsyms[pc] = sym;
	}
	free(line);
	fclose(f);
	return kallsyms;
}

void failf(const char* msg, ...)
{
	int e = errno;
	va_list args;
	va_start(args, msg);
	vfprintf(stderr, msg, args);
	va_end(args);
	fprintf(stderr, " (errno: %s)\n", strerror(e));
	exit(1);
}
