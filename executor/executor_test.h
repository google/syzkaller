// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

#ifdef __linux__
#include <sys/prctl.h>
#endif

// sys/targets also know about these consts.
static uint64 kernel_text_start = 0xc0dec0dec0000000;
static uint64 kernel_text_mask = 0xffffff;

static void os_init(int argc, char** argv, void* data, size_t data_size)
{
#ifdef __linux__
	prctl(PR_SET_PDEATHSIG, SIGKILL, 0, 0, 0);
	// There's a risk that the parent has exited before we get to call prctl().
	// In that case, let's assume that the child must have been reassigned to PID=1.
	if (getppid() == 1)
		exitf("the parent process was killed");
#endif
	void* got = mmap(data, data_size, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE | MAP_FIXED_EXCLUSIVE, -1, 0);
	if (data != got)
		failmsg("mmap of data segment failed", "want %p, got %p", data, got);
	is_kernel_64_bit = sizeof(unsigned long) == 8;
}

#ifdef __clang__
#define notrace
#else
#define notrace __attribute__((no_sanitize_coverage))
#endif

extern "C" notrace void __sanitizer_cov_trace_pc(void)
{
	if (current_thread == nullptr || current_thread->cov.data == nullptr || current_thread->cov.collect_comps)
		return;
	uint64 pc = (uint64)__builtin_return_address(0);
	// Convert to what is_kernel_pc will accept as valid coverage;
	pc = kernel_text_start | (pc & kernel_text_mask);
	// Note: we duplicate the following code instead of using a template function
	// because it must not be instrumented which is hard to achieve for all compiler
	// if the code is in a separate function.
	if (is_kernel_64_bit) {
		uint64* start = (uint64*)current_thread->cov.data;
		uint64* end = (uint64*)current_thread->cov.data_end;
		uint64 pos = start[0];
		if (start + pos + 1 < end) {
			start[0] = pos + 1;
			start[pos + 1] = pc;
		}
	} else {
		uint32* start = (uint32*)current_thread->cov.data;
		uint32* end = (uint32*)current_thread->cov.data_end;
		uint32 pos = start[0];
		if (start + pos + 1 < end) {
			start[0] = pos + 1;
			start[pos + 1] = pc;
		}
	}
}

static intptr_t execute_syscall(const call_t* c, intptr_t a[kMaxArgs])
{
	// Inject coverage PC even when built w/o coverage instrumentation.
	// This allows to pass machine check with coverage enabled.
	// pkg/fuzzer tests with coverage instrumentation shouldn't be distracted by the additional PC,
	// and syz_inject_cover overwrites the whole array so will remote it.
	__sanitizer_cov_trace_pc();
	return c->call(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8]);
}

static void cover_open(cover_t* cov, bool extra)
{
	cov->mmap_alloc_size = kCoverSize * sizeof(unsigned long);
}

static void cover_enable(cover_t* cov, bool collect_comps, bool extra)
{
	cov->collect_comps = collect_comps;
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
	cov->data_offset = is_kernel_64_bit ? sizeof(uint64_t) : sizeof(uint32_t);
	// We don't care about the specific PC values for now.
	// Once we do, we might want to consider ASLR here.
	cov->pc_offset = 0;
}

static void cover_unprotect(cover_t* cov)
{
}

static long inject_cover(cover_t* cov, long a, long b)
{
	if (cov->data == nullptr)
		return ENOENT;
	uint32 size = std::min((uint32)b, cov->mmap_alloc_size);
	memcpy(cov->data, (void*)a, size);
	memset(cov->data + size, 0xcd, std::min<uint64>(100, cov->mmap_alloc_size - size));
	return 0;
}

static long syz_inject_cover(volatile long a, volatile long b)
{
	return inject_cover(&current_thread->cov, a, b);
}

static long syz_inject_remote_cover(volatile long a, volatile long b)
{
	return inject_cover(&extra_cov, a, b);
}

static const char* setup_fault()
{
	return nullptr;
}

static const char* setup_leak()
{
	return "leak detection is not supported";
}

// Test various ways how feature setup can fail.
// We don't care about these features for test OS,
// this is just to test the feature support detection code.
#define SYZ_HAVE_FEATURES 1
static feature_t features[] = {
    {rpc::Feature::Fault, setup_fault},
    {rpc::Feature::Leak, setup_leak},
};
