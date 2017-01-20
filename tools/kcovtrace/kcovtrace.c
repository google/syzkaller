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
#include <unistd.h>

#define KCOV_INIT_TRACE _IOR('c', 1, unsigned long)
#define KCOV_ENABLE _IO('c', 100)
#define KCOV_DISABLE _IO('c', 101)
#define COVER_SIZE (16 << 20)

int main(int argc, char** argv, char** envp)
{
	int fd, pid, status;
	unsigned long *cover, n, i;

	if (argc == 1)
		fprintf(stderr, "usage: kcovtrace program [args...]\n"), exit(1);
	fd = open("/sys/kernel/debug/kcov", O_RDWR);
	if (fd == -1)
		perror("open"), exit(1);
	if (ioctl(fd, KCOV_INIT_TRACE, COVER_SIZE))
		perror("ioctl"), exit(1);
	cover = (unsigned long*)mmap(NULL, COVER_SIZE * sizeof(unsigned long),
				     PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if ((void*)cover == MAP_FAILED)
		perror("mmap"), exit(1);
	pid = fork();
	if (pid < 0)
		perror("fork"), exit(1);
	if (pid == 0) {
		if (ioctl(fd, KCOV_ENABLE, 0))
			perror("ioctl"), exit(1);
		__atomic_store_n(&cover[0], 0, __ATOMIC_RELAXED);
		execve(argv[1], argv + 1, envp);
		perror("execve");
		exit(1);
	}
	while (waitpid(-1, &status, __WALL) != pid) {
	}
	n = __atomic_load_n(&cover[0], __ATOMIC_RELAXED);
	for (i = 0; i < n; i++)
		printf("0x%lx\n", cover[i + 1]);
	if (munmap(cover, COVER_SIZE * sizeof(unsigned long)))
		perror("munmap"), exit(1);
	if (close(fd))
		perror("close"), exit(1);
	return 0;
}
