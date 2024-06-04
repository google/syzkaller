// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#include <fcntl.h>
#include <stddef.h>
#include <sys/mman.h>
#include <unistd.h>

// ShmemFile is shared memory region wrapper.
class ShmemFile
{
public:
	// Maps shared memory region of size 'size' from a new file 'file', preferably at the address 'preferred'.
	ShmemFile(const char* file, void* preferred, size_t size)
	{
		fd_ = open(file, O_RDWR | O_CREAT | O_TRUNC, 0600);
		if (fd_ == -1)
			failmsg("shmem open failed", "file=%s", file);
		if (fallocate(fd_, 0, 0, size))
			failmsg("shmem fallocate failed", "size=%zu", size);
		Mmap(fd_, preferred, size, true);
		if (unlink(file))
			fail("shmem unlink failed");
	}

	// Maps shared memory region from the file 'fd' in read/write or write-only mode.
	ShmemFile(int fd, void* preferred, size_t size, bool write)
	{
		Mmap(fd, preferred, size, write);
	}

	~ShmemFile()
	{
		if (munmap(mem_, size_))
			fail("shmem munmap failed");
		if (fd_ != -1)
			close(fd_);
	}

	// Prevents any future modifications to the region.
	void Seal()
	{
		if (mprotect(mem_, size_, PROT_READ))
			fail("shmem mprotect failed");
		if (fd_ != -1)
			close(fd_);
		fd_ = -1;
	}

	int FD() const
	{
		return fd_;
	}

	void* Mem() const
	{
		return mem_;
	}

private:
	void* mem_ = nullptr;
	size_t size_ = 0;
	int fd_ = -1;

	void Mmap(int fd, void* preferred, size_t size, bool write)
	{
		size_ = size;
		mem_ = mmap(preferred, size, PROT_READ | (write ? PROT_WRITE : 0), MAP_SHARED, fd, 0);
		if (mem_ == MAP_FAILED)
			failmsg("shmem mmap failed", "size=%zu", size);
	}

	ShmemFile(const ShmemFile&) = delete;
	ShmemFile& operator=(const ShmemFile&) = delete;
};
