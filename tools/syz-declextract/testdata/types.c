// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#include "include/syscall.h"

typedef struct { float f; } anon_t;
struct empty_struct {};
typedef int fd_t;
typedef struct forward forward_t;

struct anon_struct {
  // Various tricky anon cases.
  struct { int x; } a;
  struct {} b;
  struct { int y; };
  union { int q; long w; };
  anon_t foo;
  forward_t* forward;
  struct { int a; int b; } array[4];
  struct { int a; int b; } *ptr;
  struct { int a; int b; } *ptr_array[4];
};

enum bitfield_enum { a, b, c };

struct bitfields {
	int a : 1;
	int : 2;
	int b : 3;
	long d : 2;
	long pad : 3;
	enum bitfield_enum e : 10;
	int l : 10;
	int* p __attribute__((counted_by(l)));
} __attribute__((aligned(32)));

struct packed_t {
	char x;
	int y;
} __attribute__((packed, aligned(32)));

struct various {
	struct various* recursive;
	struct recursive* next;
	struct packed_t packed;	
};

struct recursive {
	struct various various;
};

SYSCALL_DEFINE1(types_syscall, struct anon_struct* p, struct empty_struct* y,
	struct bitfields* b, int pid, fd_t f, struct various* v) {
	return 0;
}

void  anon_flow(int x) {
	struct anon_struct s;
	s.a.x = x;
	s.y = x;
	s.w = x;
	s.foo.f = x;
	s.array[1].a = x;
	s.ptr->a = x;
	s.ptr_array[1]->b = x;
}

struct aligned_empty_struct {} __attribute__((aligned(8)));
struct large_struct { long foo[10]; };

struct align1 {
	char f1;
	long aligner[0];
	char f2;
};

struct align2 {
	char f1;
	struct empty_struct aligner;
	char f2;
};

struct align3 {
	char f1;
	struct aligned_empty_struct aligner;
	char f2;
};

struct align4 {
	char f1;
	struct large_struct aligner[0];
	char f2;
};

SYSCALL_DEFINE1(align_syscall, struct align1* a1, struct align2* a2, struct align3* a3, struct align4* a4) {
	return 0;
}

