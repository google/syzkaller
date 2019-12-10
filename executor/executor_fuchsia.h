// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#include <errno.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <zircon/process.h>
#include <zircon/status.h>
#include <zircon/syscalls.h>

#define MAX_COVSZ (1ULL << 20)

// In x86_64, sancov stores the return address - 1.
// We add 1 so the stored value points to a valid pc.
static const uint64_t kPcFixup = 1;

struct cover_ctx_t {
	uint64_t cover_data_raw[MAX_COVSZ];
	uint32_t cover_data_truncated[MAX_COVSZ];
	zx_handle_t covcount_vmo;
};

static __thread cover_ctx_t cover;

static void cover_open(cover_t* cov, bool extra)
{
}

static void cover_enable(cover_t* cov, bool collect_comps, bool extra)
{
	zx_status_t status = zx_coverage_control(zx_thread_self(), 1, &cover.covcount_vmo);
	if (status != ZX_OK) {
		fail("failed to enable coverage. err: %d", status);
	}
}

static void cover_reset(cover_t* cov)
{
	zx_status_t status = zx_coverage_control(zx_thread_self(), 2, nullptr);

	if (status != ZX_OK) {
	  fail("failed to reset coverage. err: %d", status);
	}
}

static void cover_collect(cover_t* cov)
{
zx_status_t status;
	uint64_t cov_count;
	status = zx_vmo_read(cover.covcount_vmo, &cov_count, 0, sizeof(cov_count));
	if (status != ZX_OK) {
	fail("failed to read kcov size: %d", status);
}
	if (cov_count > MAX_COVSZ - 1) {
	  cov_count = MAX_COVSZ - 1;
	}

	debug("coverage size: %zu\n", cov_count);

	status = zx_vmo_read(cover.covcount_vmo, cover.cover_data_raw, sizeof(uint64_t), cov_count * sizeof(uint64_t));
	if (status != ZX_OK) {
	fail("failed to read kcov data: %d",status);
}

	for (size_t i = 0; i < cov_count; i++) {
		cover.cover_data_truncated[i] = static_cast<uint32_t>((cover.cover_data_raw[i] + kPcFixup) & 0xFFFFFFFF);
	}

	cov->size = cov_count;
	cov->data = reinterpret_cast<char*>(cover.cover_data_truncated);
}

static void cover_protect(cover_t* cov)
{
}

static void os_init(int argc, char** argv, void* data, size_t data_size)
{
	zx_status_t status = syz_mmap((size_t)data, data_size);
	if (status != ZX_OK)
		fail("mmap of data segment failed: %s (%d)", zx_status_get_string(status), status);
}

static intptr_t execute_syscall(const call_t* c, intptr_t a[kMaxArgs])
{
	intptr_t res = c->call(a[0], a[1], a[2], a[3], a[4], a[5], a[6], a[7], a[8]);
	if (strncmp(c->name, "zx_", 3) == 0) {
		// Convert zircon error convention to the libc convention that executor expects.
		// The following calls return arbitrary integers instead of error codes.
		if (res == ZX_OK ||
		    !strcmp(c->name, "zx_debuglog_read") ||
		    !strcmp(c->name, "zx_clock_get") ||
		    !strcmp(c->name, "zx_clock_get_monotonic") ||
		    !strcmp(c->name, "zx_deadline_after") ||
		    !strcmp(c->name, "zx_ticks_get"))
			return 0;
		errno = (-res) & 0x7f;
		return -1;
	}
	// We cast libc functions to signature returning intptr_t,
	// as the result int -1 is returned as 0x00000000ffffffff rather than full -1.
	if (res == 0xffffffff)
		res = (intptr_t)-1;
	return res;
}

void write_call_output(thread_t* th, bool finished)
{
	uint32 reserrno = 999;
	const bool blocked = th != last_scheduled;
	uint32 call_flags = call_flag_executed | (blocked ? call_flag_blocked : 0);
	if (finished) {
		reserrno = th->res != -1 ? 0 : th->reserrno;
		call_flags |= call_flag_finished |
			      (th->fault_injected ? call_flag_fault_injected : 0);
	}
	call_reply reply;
	reply.header.magic = kOutMagic;
	reply.header.done = 0;
	reply.header.status = 0;
	reply.call_index = th->call_index;
	reply.call_num = th->call_num;
	reply.reserrno = reserrno;
	reply.flags = call_flags;
	reply.signal_size = 0;
	reply.cover_size = 0;
	reply.comps_size = 0;
	if (flag_coverage) {
		reply.signal_size = th->cov.size;
		if (flag_collect_cover) {
			reply.cover_size = th->cov.size;
		}
	}
	if (write(kOutPipeFd, &reply, sizeof(reply)) != sizeof(reply))
		fail("control pipe call write failed");

	if (flag_coverage) {
		// In Fuchsia, coverage is collected by instrumenting edges instead of
		// basic blocks. This means that the signal that syzkaller
		// understands is the same as the coverage PCs.
		ssize_t wrote = write(kOutPipeFd, th->cov.data, th->cov.size * sizeof(uint32_t));
		if (wrote != sizeof(uint32_t) * th->cov.size) {
			fail("signals table write failed. Wrote %zd", wrote);
		}
		if (!flag_collect_cover) {
			return;
		}
		wrote = write(kOutPipeFd, th->cov.data, th->cov.size * sizeof(uint32_t));
		if (wrote != sizeof(uint32_t) * th->cov.size) {
			fail("coverage table write failed. Wrote %zd", wrote);
		}
	}

	debug_verbose("out: index=%u num=%u errno=%d finished=%d blocked=%d\n",
		      th->call_index, th->call_num, reserrno, finished, blocked);
}
