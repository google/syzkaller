// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

static void os_init(int argc, char** argv, void* data, size_t data_size)
{
	void* got = mmap(data, data_size, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE | MAP_FIXED, -1, 0);
	if (data != got)
		failmsg("mmap of data segment failed", "want %p, got %p", data, got);
	is_kernel_64_bit = sizeof(unsigned long) == 8;
}

static intptr_t execute_syscall(const call_t* c, intptr_t a[kMaxArgs])
{
	return c->call(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8]);
}

static __thread unsigned long* local_cover_start = NULL;
static __thread unsigned long* local_cover_end = NULL;

#ifdef __clang__
#define notrace
#else
#define notrace __attribute__((no_sanitize_coverage))
#endif

extern "C" notrace void __sanitizer_cov_trace_pc(void)
{
	unsigned long ip = (unsigned long)__builtin_return_address(0);
	unsigned long* start = local_cover_start;
	unsigned long* end = local_cover_end;
	if (start == NULL || end == NULL)
		return;
	int pos = start[0];
	if (start + pos + 1 < end) {
		start[0] = pos + 1;
		start[pos + 1] = ip;
	}
}

static void cover_open(cover_t* cov, bool extra)
{
	cov->mmap_alloc_size = kCoverSize * sizeof(unsigned long);
}

static void cover_enable(cover_t* cov, bool collect_comps, bool extra)
{
	local_cover_start = (unsigned long*)cov->data;
	local_cover_end = (unsigned long*)cov->data_end;
}

static void cover_reset(cover_t* cov)
{
	*(unsigned long*)(cov->data) = 0;
}

static void cover_collect(cover_t* cov)
{
	cov->size = *(unsigned long*)(cov->data);
}

static void cover_protect(cover_t* cov)
{
}

static void cover_mmap(cover_t* cov)
{
	if (cov->data != NULL)
		fail("cover_mmap invoked on an already mmapped cover_t object");
	if (cov->mmap_alloc_size == 0)
		fail("cover_t structure is corrupted");
	cov->data = (char*)mmap(NULL, cov->mmap_alloc_size,
				PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
	if (cov->data == MAP_FAILED)
		exitf("cover mmap failed");
	cov->data_end = cov->data + cov->mmap_alloc_size;
	cov->data_offset = sizeof(unsigned long);
	// We don't care about the specific PC values for now.
	// Once we do, we might want to consider ASLR here.
	cov->pc_offset = 0;
}

#if SYZ_EXECUTOR_USES_SHMEM
static void cover_unprotect(cover_t* cov)
{
}

static bool use_cover_edges(uint64 pc)
{
	return true;
}
#endif
