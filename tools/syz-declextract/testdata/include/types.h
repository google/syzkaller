// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

typedef signed char s8;
typedef short s16;
typedef int s32;
typedef long long s64;
typedef unsigned char u8;
typedef unsigned short u16;
typedef unsigned int u32;
typedef unsigned long long u64;

#define ARRAY_SIZE(x) (sizeof(x)/sizeof((x)[0]))

static inline u32 atomic_load32(u32* p) {
	return __atomic_load_n(p, __ATOMIC_RELAXED);
}

inline u64 atomic_load64(u64* p) {
	return __atomic_load_n(p, __ATOMIC_RELAXED);
}
