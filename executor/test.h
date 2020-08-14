// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#if GOOS_linux && GOARCH_amd64
#include "test_linux.h"
#endif

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

static struct {
	const char* name;
	int (*f)();
} tests[] = {
    {"test_copyin", test_copyin},
    {"test_csum_inet", test_csum_inet},
    {"test_csum_inet_acc", test_csum_inet_acc},
#if GOOS_linux && GOARCH_amd64
    {"test_kvm", test_kvm},
#endif
};

static int run_tests()
{
	int ret = 0;
	for (size_t i = 0; i < ARRAY_SIZE(tests); i++) {
		const char* name = tests[i].name;
		printf("=== RUN  %s\n", name);
		int res = tests[i].f();
		ret |= res > 0;
		const char* strres = res < 0 ? "SKIP" : (res > 0 ? "FAIL" : "OK");
		printf("--- %-4s %s\n", strres, name);
	}
	return ret;
}
