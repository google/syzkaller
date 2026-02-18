// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#if GOOS_linux && (GOARCH_amd64 || GOARCH_ppc64 || GOARCH_ppc64le || GOARCH_arm64)
#include "test_linux.h"
#endif

#include <algorithm>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include "executor_common.h"

static int test_copyin()
{
	static uint16 buf[3];
	STORE_BY_BITMASK(uint16, htole16, &buf[1], 0x1234, 0, 16);
	unsigned char x[sizeof(buf)];
	memcpy(x, buf, sizeof(x));
	if (x[0] != 0 || x[1] != 0 ||
	    x[2] != 0x34 || x[3] != 0x12 ||
	    x[4] != 0 || x[5] != 0) {
		printf("bad result of STORE_BY_BITMASK(le16, 0x1234, 0, 16): %x %x %x %x %x %x\n",
		       x[0], x[1], x[2], x[3], x[4], x[5]);
		return 1;
	}
	STORE_BY_BITMASK(uint16, htole16, &buf[1], 0x555a, 5, 4);
	memcpy(x, buf, sizeof(x));
	if (x[0] != 0 || x[1] != 0 ||
	    x[2] != 0x54 || x[3] != 0x13 ||
	    x[4] != 0 || x[5] != 0) {
		printf("bad result of STORE_BY_BITMASK(le16, 0x555a, 5, 4): %x %x %x %x %x %x\n",
		       x[0], x[1], x[2], x[3], x[4], x[5]);
		return 1;
	}
	STORE_BY_BITMASK(uint16, htobe16, &buf[1], 0x4567, 13, 3);
	memcpy(x, buf, sizeof(x));
	if (x[0] != 0 || x[1] != 0 ||
	    x[2] != 0xf4 || x[3] != 0x13 ||
	    x[4] != 0 || x[5] != 0) {
		printf("bad result of STORE_BY_BITMASK(be16, 0x4567, 13, 3): %x %x %x %x %x %x\n",
		       x[0], x[1], x[2], x[3], x[4], x[5]);
		return 1;
	}
	return 0;
}

static int test_csum_inet()
{
	struct csum_inet_test {
		const char* data;
		size_t length;
		uint16 csum;
	};
	struct csum_inet_test tests[] = {
	    {// 0
	     "",
	     0,
	     le16toh(0xffff)},
	    {
		// 1
		"\x00",
		1,
		le16toh(0xffff),
	    },
	    {
		// 2
		"\x00\x00",
		2,
		le16toh(0xffff),
	    },
	    {
		// 3
		"\x00\x00\xff\xff",
		4,
		le16toh(0x0000),
	    },
	    {
		// 4
		"\xfc",
		1,
		le16toh(0xff03),
	    },
	    {
		// 5
		"\xfc\x12",
		2,
		le16toh(0xed03),
	    },
	    {
		// 6
		"\xfc\x12\x3e",
		3,
		le16toh(0xecc5),
	    },
	    {
		// 7
		"\xfc\x12\x3e\x00\xc5\xec",
		6,
		le16toh(0x0000),
	    },
	    {
		// 8
		"\x42\x00\x00\x43\x44\x00\x00\x00\x45\x00\x00\x00\xba\xaa\xbb\xcc\xdd",
		17,
		le16toh(0x43e1),
	    },
	    {
		// 9
		"\x42\x00\x00\x43\x44\x00\x00\x00\x45\x00\x00\x00\xba\xaa\xbb\xcc\xdd\x00",
		18,
		le16toh(0x43e1),
	    },
	    {
		// 10
		"\x00\x00\x42\x00\x00\x43\x44\x00\x00\x00\x45\x00\x00\x00\xba\xaa\xbb\xcc\xdd",
		19,
		le16toh(0x43e1),
	    },
	    {
		// 11
		"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\xab\xcd",
		15,
		le16toh(0x5032),
	    },
	    {
		// 12
		"\x00\x00\x12\x34\x56\x78",
		6,
		le16toh(0x5397),
	    },
	    {
		// 13
		"\x00\x00\x12\x34\x00\x00\x56\x78\x00\x06\x00\x04\xab\xcd",
		14,
		le16toh(0x7beb),
	    },
	    {
		// 14
		"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff\xff\xee\xdd\xcc\xbb\xaa\x99\x88\x77\x66\x55\x44\x33\x22\x11\x00\x00\x00\x00\x04\x00\x00\x00\x06\x00\x00\xab\xcd",
		44,
		le16toh(0x2854),
	    },
	    {
		// 15
		"\x00\x00\x12\x34\x00\x00\x56\x78\x00\x11\x00\x04\xab\xcd",
		14,
		le16toh(0x70eb),
	    },
	    {
		// 16
		"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff\xff\xee\xdd\xcc\xbb\xaa\x99\x88\x77\x66\x55\x44\x33\x22\x11\x00\x00\x00\x00\x04\x00\x00\x00\x11\x00\x00\xab\xcd",
		44,
		le16toh(0x1d54),
	    },
	    {
		// 17
		"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff\xff\xee\xdd\xcc\xbb\xaa\x99\x88\x77\x66\x55\x44\x33\x22\x11\x00\x00\x00\x00\x04\x00\x00\x00\x3a\x00\x00\xab\xcd",
		44,
		le16toh(0xf453),
	    }};

	for (unsigned i = 0; i < ARRAY_SIZE(tests); i++) {
		struct csum_inet csum;
		csum_inet_init(&csum);
		csum_inet_update(&csum, (const uint8*)tests[i].data, tests[i].length);
		if (csum_inet_digest(&csum) != tests[i].csum) {
			fprintf(stderr, "bad checksum in test #%u, want: %hx, got: %hx\n", i, tests[i].csum, csum_inet_digest(&csum));
			return 1;
		}
	}

	return 0;
}

static int rand_int_range(int start, int end)
{
	return rand() % (end + 1 - start) + start;
}

static int test_csum_inet_acc()
{
	uint8 buffer[128];

	for (int test = 0; test < 256; test++) {
		int size = rand_int_range(1, 128);
		int step = rand_int_range(1, 8) * 2;

		for (int i = 0; i < size; i++)
			buffer[i] = rand_int_range(0, 255);

		struct csum_inet csum_acc;
		csum_inet_init(&csum_acc);

		for (int i = 0; i < size / step; i++)
			csum_inet_update(&csum_acc, &buffer[i * step], step);
		if (size % step != 0)
			csum_inet_update(&csum_acc, &buffer[size - size % step], size % step);

		struct csum_inet csum;
		csum_inet_init(&csum);
		csum_inet_update(&csum, &buffer[0], size);

		if (csum_inet_digest(&csum_acc) != csum_inet_digest(&csum))
			return 1;
	}
	return 0;
}

static int test_cover_filter()
{
	CoverFilter filter;
	CoverFilter child(filter.FD());

	std::vector<uint64> pcs = {
	    100,
	    111,
	    200,
	    (1 << 20) - 1,
	    1 << 20,
	    (1 << 30) - 1,
	    100ull << 30,
	    (100ull << 30) + 100,
	    200ull << 30,
	    (1ull << 62) + 100,
	};

	// These we don't insert, but they are also present due to truncation of low 3 bits.
	std::vector<uint64> also_contain = {
	    96,
	    103,
	    104,
	    207,
	    (1 << 20) - 7,
	    (1 << 20) + 7,
	    (1ull << 62) + 96,
	    (1ull << 62) + 103,
	};

	std::vector<uint64> dont_contain = {
	    0,
	    1,
	    95,
	    112,
	    199,
	    208,
	    100 << 10,
	    (1 << 20) - 9,
	    (1 << 20) + 8,
	    (2ull << 30) - 1,
	    2ull << 30,
	    (2ull << 30) + 1,
	    (100ull << 30) + 108,
	    150ull << 30,
	    1ull << 40,
	    1ull << 63,
	    ~0ull,
	};

	int ret = 0;
	for (auto pc : pcs)
		filter.Insert(pc);
	pcs.insert(pcs.end(), also_contain.begin(), also_contain.end());
	for (auto pc : pcs) {
		if (!filter.Contains(pc) || !child.Contains(pc)) {
			printf("filter doesn't contain %llu (0x%llx)\n", pc, pc);
			ret = 1;
		}
	}
	for (auto pc : dont_contain) {
		if (filter.Contains(pc) || child.Contains(pc)) {
			printf("filter contains %llu (0x%llx)\n", pc, pc);
			ret = 1;
		}
	}
	return ret;
}

static bool test_one_glob(const char* pattern, std::vector<std::string> want)
{
	std::vector<std::string> got = Glob(pattern);
	std::sort(want.begin(), want.end());
	std::sort(got.begin(), got.end());
	if (got == want)
		return true;
	printf("pattern '%s', want %zu files:\n", pattern, want.size());
	for (const auto& f : want)
		printf("\t'%s'\n", f.c_str());
	printf("got %zu files:\n", got.size());
	for (const auto& f : got)
		printf("\t'%s'\n", f.c_str());
	return false;
}

static void must_mkdir(const char* dir)
{
	if (mkdir(dir, 0700))
		failmsg("mkdir failed", "dir=%s", dir);
}

static void must_creat(const char* file)
{
	int fd = open(file, O_CREAT | O_EXCL, 0700);
	if (fd == -1)
		failmsg("open failed", "file=%s", file);
	close(fd);
}

static void must_link(const char* oldpath, const char* linkpath)
{
	if (link(oldpath, linkpath))
		failmsg("link failed", "oldpath=%s linkpath=%s", oldpath, linkpath);
}

static void must_symlink(const char* oldpath, const char* linkpath)
{
	if (symlink(oldpath, linkpath))
		failmsg("symlink failed", "oldpath=%s linkpath=%s", oldpath, linkpath);
}

static int test_glob()
{
#if GOARCH_arm
	// When running a 32-bit ARM binary on a 64-bit system under QEMU, readdir() fails
	// with EOVERFLOW, resulting in Glob() returning 0 files.
	// Tracking QEMU bug: https://gitlab.com/qemu-project/qemu/-/issues/263.
	return -1;
#endif
	// Note: pkg/runtest.TestExecutor creates a temp dir for the test,
	// so we create files in cwd and don't clean up.
	if (!test_one_glob("glob/*", {}))
		return 1;
	must_mkdir("glob");
	if (!test_one_glob("glob/*", {}))
		return 1;
	must_mkdir("glob/dir1");
	must_creat("glob/file1");
	must_mkdir("glob/dir2");
	must_creat("glob/dir2/file21");
	must_mkdir("glob/dir3");
	must_creat("glob/dir3/file31");
	must_link("glob/dir3/file31", "glob/dir3/file32");
	must_symlink("file31", "glob/dir3/file33");
	must_symlink("deadlink", "glob/dir3/file34");
	must_symlink("../../glob", "glob/dir3/dir31");
	must_mkdir("glob/dir4");
	must_mkdir("glob/dir4/dir41");
	must_creat("glob/dir4/dir41/file411");
	must_symlink("dir4", "glob/dir5");
	must_mkdir("glob/dir6");
	must_mkdir("glob/dir6/dir61");
	must_creat("glob/dir6/dir61/file611");
	must_symlink("dir6/dir61", "glob/self");
	// Directories are not includes + not recursive (yet).
	if (!test_one_glob("glob/*", {
					 "glob/file1",
				     }))
		return 1;
	if (!test_one_glob("glob/*/*", {
					   "glob/dir2/file21",
					   "glob/dir3/file31",
					   "glob/dir3/file32", // hard links are included
					   "glob/self/file611", // symlinks via name "self" are included
				       }))
		return 1;
	return 0;
}

static int test_get_last_opt()
{
	struct {
		const char* cmdline;
		const char* key;
		const char* want;
	} tests[] = {
	    {"key=val", "key", "val"},
	    {"key=val ", "key", "val"},
	    {" key=val", "key", "val"},
	    {" key=val ", "key", "val"},
	    {"key=val1 key=val2", "key", "val2"},
	    {"key=val1 key=val2 ", "key", "val2"},
	    {"key=val1 key=val2 key=val3", "key", "val3"},
	    {"other=val key=val", "key", "val"},
	    {"key=val other=val", "key", "val"},
	    {"foo=bar", "key", ""},
	    {"nokey=val", "key", ""},
	    {"key", "key", ""},
	    {"full match", "full", ""}, // "full" != "full="
	};

	char buf[128];
	for (size_t i = 0; i < sizeof(tests) / sizeof(tests[0]); i++) {
		memset(buf, 0, sizeof(buf));
		get_last_opt(tests[i].cmdline, tests[i].key, buf, sizeof(buf));
		if (strcmp(buf, tests[i].want) != 0) {
			printf("test_get_last_opt failed: cmdline='%s' key='%s' want='%s' got='%s'\n",
			       tests[i].cmdline, tests[i].key, tests[i].want, buf);
			return 1;
		}
	}

	char small_buf[4];
	get_last_opt("key=value", "key", small_buf, sizeof(small_buf));
	if (strcmp(small_buf, "val") != 0) {
		printf("test_get_last_opt truncation failed: want='val' got='%s'\n", small_buf);
		return 1;
	}

	return 0;
}

static struct {
	const char* name;
	int (*f)();
} tests[] = {
    {"test_copyin", test_copyin},
    {"test_csum_inet", test_csum_inet},
    {"test_csum_inet_acc", test_csum_inet_acc},
#if GOOS_linux && (GOARCH_amd64 || GOARCH_ppc64 || GOARCH_ppc64le || GOARCH_arm64)
    {"test_kvm", test_kvm},
#endif
#if GOOS_linux && GOARCH_arm64
    {"test_syzos", test_syzos},
#endif
    {"test_cover_filter", test_cover_filter},
    {"test_glob", test_glob},
    {"test_get_last_opt", test_get_last_opt},
};

static int run_tests(const char* test)
{
	int ret = 0;
	for (size_t i = 0; i < ARRAY_SIZE(tests); i++) {
		const char* name = tests[i].name;
		if (test && strcmp(test, name))
			continue;
		printf("=== RUN  %s\n", name);
		int res = tests[i].f();
		ret |= res > 0;
		const char* strres = res < 0 ? "SKIP" : (res > 0 ? "FAIL" : "OK");
		printf("--- %-4s %s\n", strres, name);
	}
	return ret;
}
