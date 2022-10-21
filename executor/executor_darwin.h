// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#include <math.h>
#include <sys/ioctl.h>
#include <sys/mman.h>

// FIXME(HerrSpace): As executor is written in C++, we need to make this patch:
// -struct ksancov_trace *trace = (void *)mc.ptr; into
// +struct ksancov_trace *trace = (ksancov_trace *)mc.ptr;
// twice to make this header compile. This used to be C++ friendly in Catalina,
// but was broken in xnu source drop 7195.50.7.100.1.
#include <ksancov.h>

static void os_init(int argc, char** argv, void* data, size_t data_size)
{
	// Note: We use is_kernel_64_bit in executor.cc to decide which PC pointer
	// size to expect. However in KSANCOV we always get back 32bit pointers,
	// which then get reconstructed to 64bit pointers by adding a fixed offset.
	is_kernel_64_bit = false;

	int prot = PROT_READ | PROT_WRITE | PROT_EXEC;
	int flags = MAP_ANON | MAP_PRIVATE | MAP_FIXED;

	void* got = mmap(data, data_size, prot, flags, -1, 0);
	if (data != got)
		failmsg("mmap of data segment failed", "want %p, got %p", data, got);

	// Makes sure the file descriptor limit is sufficient to map control pipes.
	struct rlimit rlim;
	rlim.rlim_cur = rlim.rlim_max = kMaxFd;
	setrlimit(RLIMIT_NOFILE, &rlim);
}

static intptr_t execute_syscall(const call_t* c, intptr_t a[kMaxArgs])
{
	if (c->call)
		return c->call(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8]);

	return __syscall(c->sys_nr, a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8]);
}

static void cover_open(cover_t* cov, bool extra)
{
	int fd = ksancov_open();
	if (fd == -1)
		fail("open of /dev/ksancov failed");
	if (dup2(fd, cov->fd) < 0)
		failmsg("failed to dup cover fd", "from=%d, to=%d", fd, cov->fd);
	close(fd);

	// Note: In the other KCOV implementations we pass the shared memory size
	// to the initial ioctl, before mmaping. KSANCOV reversed this logic.
	// Here we instead pass the maximum number of traced PCs to the initial
	// KSANCOV_IOC_TRACE ioctl. We then pass a size_t pointer to the second
	// KSANCOV_IOC_MAP ioctl, hence the kernel is instead telling us the final
	// size. We have a sanity check in executor.cc checking that cov.size isn't
	// larger or equal to kCoverSize. To make sure that assumption holds, we're
	// calculating the max_entries accordingly.
	size_t max_entries = floor(
	    (kCoverSize - sizeof(struct ksancov_trace)) / sizeof(uint32_t));

	// Note: XNUs KSANCOV API forces us to choose the mode after opening the
	// device and before mmaping the coverage buffer. As the function we are
	// in, cover_open(), expects us to mmap here, we are forced to commit to a
	// mode here as well. For other OSes we commit to a mode in cover_enable(),
	// based on collect_comps. This is not really a problem though, as TRACE_PC
	// is the only relevant mode for us for now. XNU doesn't support TRACE_CMP
	// and we don't care about the counters/nedges modes in XNU.
	if (ksancov_mode_trace(cov->fd, max_entries))
		fail("ioctl init trace write failed");
}

static void cover_mmap(cover_t* cov)
{
	if (cov->data != NULL)
		fail("cover_mmap invoked on an already mmapped cover_t object");
	uintptr_t mmap_ptr = 0;
	if (ksancov_map(cov->fd, &mmap_ptr, &cov->mmap_alloc_size))
		fail("cover mmap failed");

	// Sanity check to make sure our assumptions in the max_entries calculation
	// hold up.
	if (cov->mmap_alloc_size > kCoverSize)
		fail("mmap allocation size larger than anticipated");

	cov->data = (char*)mmap_ptr;
	cov->data_end = cov->data + cov->mmap_alloc_size;
}

static void cover_protect(cover_t* cov)
{
}

static void cover_unprotect(cover_t* cov)
{
}

static void cover_enable(cover_t* cov, bool collect_comps, bool extra)
{
	if (collect_comps)
		fail("TRACE_CMP not implemented on darwin");
	if (extra)
		fail("Extra coverage collection not implemented on darwin");
	// Note: we are already comitted to TRACE_PC here, hence we don't make use
	// of collect_comps. For more details see the comment in cover_open().
	if (ksancov_thread_self(cov->fd))
		exitf("cover enable write trace failed");
}

static void cover_reset(cover_t* cov)
{
	ksancov_reset((struct ksancov_header*)cov->data);
	ksancov_start((struct ksancov_header*)cov->data);
}

static void cover_collect(cover_t* cov)
{
	struct ksancov_trace* trace = (struct ksancov_trace*)cov->data;
	cov->size = ksancov_trace_head(trace);
	cov->data_offset = ((int64_t) & (trace->pcs)) - ((int64_t)(cov->data));
	cov->pc_offset = trace->offset;
}

static bool use_cover_edges(uint64 pc)
{
	return true;
}
