// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// kcovtrace is like strace but show kernel coverage collected with KCOV.
// It is very simplistic at this point and does not support multithreaded processes, etc.
// It can be used to understand, for example, exact location where kernel bails out
// with an error for a particular syscall.

#include <fcntl.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#if defined(__FreeBSD__) || defined(__NetBSD__)
#include <sys/kcov.h>
#define KCOV_PATH "/dev/kcov"
typedef uint64_t cover_t;
#else
#define KCOV_INIT_TRACE _IOR('c', 1, unsigned long)
#define KCOV_ENABLE _IO('c', 100)
#define KCOV_DISABLE _IO('c', 101)
#define KCOV_ENTRY_SIZE sizeof(unsigned long)
#define KCOV_PATH "/sys/kernel/debug/kcov"
#define KCOV_TRACE_PC 0
typedef unsigned long cover_t;
#endif
#define COVER_SIZE (16 << 20)

int main(int argc, char** argv, char** envp)
{
	int fd, pid, status;
	cover_t *cover, n, i;

	if (argc == 1)
		fprintf(stderr, "usage: kcovtrace program [args...]\n"), exit(1);
	fd = open(KCOV_PATH, O_RDWR);
	if (fd == -1)
		perror("open"), exit(1);
#if defined(__FreeBSD__)
	if (ioctl(fd, KIOSETBUFSIZE, COVER_SIZE))
#elif defined(__NetBSD__)
	uint64_t cover_size = COVER_SIZE;
	if (ioctl(fd, KCOV_IOC_SETBUFSIZE, &cover_size))
#else
	if (ioctl(fd, KCOV_INIT_TRACE, COVER_SIZE))
#endif
		perror("ioctl"), exit(1);
	cover = (cover_t*)mmap(NULL, COVER_SIZE * KCOV_ENTRY_SIZE,
			       PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if ((void*)cover == MAP_FAILED)
		perror("mmap"), exit(1);
	pid = fork();
	if (pid < 0)
		perror("fork"), exit(1);
	if (pid == 0) {
#if defined(__FreeBSD__)
		if (ioctl(fd, KIOENABLE, KCOV_MODE_TRACE_PC))
#elif defined(__NetBSD__)
		int kcov_mode = KCOV_MODE_TRACE_PC;
		if (ioctl(cov->fd, KCOV_IOC_ENABLE, &kcov_mode))
#else
		if (ioctl(fd, KCOV_ENABLE, KCOV_TRACE_PC))
#endif
			perror("ioctl"), exit(1);
		__atomic_store_n(&cover[0], 0, __ATOMIC_RELAXED);
		execve(argv[1], argv + 1, envp);
		perror("execve");
		exit(1);
	}
#if defined(__FreeBSD__)
	while (waitpid(-1, &status, 0) != pid) {
#else
	while (waitpid(-1, &status, __WALL) != pid) {
#endif
	}
	n = __atomic_load_n(&cover[0], __ATOMIC_RELAXED);
	for (i = 0; i < n; i++)
		printf("0x%jx\n", (uintmax_t)cover[i + 1]);
	if (munmap(cover, COVER_SIZE * KCOV_ENTRY_SIZE))
		perror("munmap"), exit(1);
	if (close(fd))
		perror("close"), exit(1);
	return 0;
}
