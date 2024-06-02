// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>

struct cov_filter_t {
	uint64 pcstart;
	uint64 pcsize;
	uint8 bitmap[];
};

static cov_filter_t* cov_filter;

static void init_coverage_filter(char* filename)
{
	int f = open(filename, O_RDONLY);
	if (f < 0) {
		// We don't fail here because we don't know yet if we should use coverage filter or not.
		// We will receive the flag only in execute flags and will fail in coverage_filter if necessary.
		debug("bitmap is not found, coverage filter disabled\n");
		return;
	}
	struct stat st;
	if (fstat(f, &st))
		fail("faied to stat coverage filter");
	// A random address for bitmap. Don't corrupt output_data.
	void* preferred = (void*)0x110f230000ull;
	cov_filter = (cov_filter_t*)mmap(preferred, st.st_size, PROT_READ, MAP_PRIVATE, f, 0);
	if (cov_filter != preferred)
		failmsg("failed to mmap coverage filter bitmap", "want=%p, got=%p", preferred, cov_filter);
	if ((uint32)st.st_size != sizeof(uint64) * 2 + ((cov_filter->pcsize >> 4) / 8 + 2))
		fail("bad coverage filter bitmap size");
	close(f);
}

static bool coverage_filter(uint64 pc)
{
	if (!flag_coverage_filter)
		return true;
	if (cov_filter == NULL)
		fail("coverage filter was enabled but bitmap initialization failed");
	// Prevent out of bound while searching bitmap.
	if (pc < cov_filter->pcstart || pc > cov_filter->pcstart + cov_filter->pcsize)
		return false;
	// For minimizing the size of bitmap, the lowest 4-bit will be dropped.
	pc -= cov_filter->pcstart;
	pc = pc >> 4;
	uint64 idx = pc / 8;
	uint64 shift = pc % 8;
	return (cov_filter->bitmap[idx] & (1 << shift)) > 0;
}
