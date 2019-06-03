// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

static void cover_open(cover_t* cov, bool extra)
{
}

static void cover_enable(cover_t* cov, bool collect_comps, bool extra)
{
}

static void cover_reset(cover_t* cov)
{
}

static void cover_collect(cover_t* cov)
{
}

static void cover_protect(cover_t* cov)
{
}

#if SYZ_EXECUTOR_USES_SHMEM
static void cover_unprotect(cover_t* cov)
{
}

static bool cover_check(uint32 pc)
{
	return true;
}

static bool cover_check(uint64 pc)
{
	return true;
}
#endif
