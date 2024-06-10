// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

static uint64 kernel_text_start = 0xc0dec0dec0000000;
static uint64 kernel_text_mask = 0xffffff;

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

#ifdef __clang__
#define notrace
#else
#define notrace __attribute__((no_sanitize_coverage))
#endif

extern "C" notrace void __sanitizer_cov_trace_pc(void)
{
	unsigned long ip = (unsigned long)__builtin_return_address(0);
	// Convert to what is_kernel_pc will accept as valid coverage;
	ip = kernel_text_start | (ip & kernel_text_mask);
	if (current_thread == nullptr || current_thread->cov.data == nullptr)
		return;
	unsigned long* start = (unsigned long*)current_thread->cov.data;
	unsigned long* end = (unsigned long*)current_thread->cov.data_end;
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
}

static void cover_reset(cover_t* cov)
{
	*(uint64*)(cov->data) = 0;
}

static void cover_collect(cover_t* cov)
{
	if (is_kernel_64_bit)
		cov->size = *(uint64*)cov->data;
	else
		cov->size = *(uint32*)cov->data;
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

static void cover_unprotect(cover_t* cov)
{
}

static bool is_kernel_data(uint64 addr)
{
	return addr >= 0xda1a0000 && addr <= 0xda1a1000;
}

static int is_kernel_pc(uint64 pc)
{
	uint64 start = kernel_text_start;
	uint64 end = kernel_text_start | kernel_text_mask;
	if (!is_kernel_64_bit) {
		start = (uint32)start;
		end = (uint32)end;
	}
	return pc >= start && pc <= end ? 1 : -1;
}

static bool use_cover_edges(uint64 pc)
{
	return true;
}

static long syz_inject_cover(volatile long a, volatile long b, volatile long c)
{
	cover_t* cov = &current_thread->cov;
	if (cov->data == nullptr)
		return ENOENT;
	is_kernel_64_bit = a;
	cov->data_offset = is_kernel_64_bit ? sizeof(uint64_t) : sizeof(uint32_t);
	uint32 size = std::min((uint32)c, cov->mmap_alloc_size);
	memcpy(cov->data, (void*)b, size);
	memset(cov->data + size, 0xcd, std::min<uint64>(100, cov->mmap_alloc_size - size));
	return 0;
}
