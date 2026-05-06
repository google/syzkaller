#define _GNU_SOURCE
#include "../race_toolkit.h"
#include <assert.h>
#include <errno.h>
#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

static int flag = 0;
void* wait_thread(void* arg)
{
	WAIT_ON(&flag, 1);
	return NULL;
}

void test_wait_on_signal()
{
	pthread_t t;
	pthread_create(&t, NULL, wait_thread, NULL);
	sleep(1);
	SIGNAL(&flag, 1);
	pthread_join(t, NULL);
	printf("test_wait_on_signal passed\n");
}

void* event_thread(void* arg)
{
	event_t* ev = (event_t*)arg;
	event_wait(ev);
	return NULL;
}

void test_event()
{
	event_t ev;
	event_init(&ev);
	pthread_t t;
	pthread_create(&t, NULL, event_thread, &ev);
	sleep(1);
	event_set(&ev);
	pthread_join(t, NULL);
	printf("test_event passed\n");
}

void test_setup_uffd()
{
	size_t len = 4096;
	void* addr = mmap(NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
	assert(addr != MAP_FAILED);

	int uffd = setup_uffd(addr, len);
	if (uffd == -1) {
		if (errno == EPERM || errno == ENOSYS) {
			printf("setup_uffd skipped (missing privileges or not supported)\n");
		} else {
			perror("setup_uffd");
			exit(1);
		}
	} else {
		printf("setup_uffd passed\n");
		close(uffd);
	}
	munmap(addr, len);
}

void test_pin_to_cpu()
{
	PIN_TO_CPU(0);
	printf("test_pin_to_cpu passed\n");
}

int main()
{
	SETUP_UNBUFFERED_IO();
	test_pin_to_cpu();
	test_wait_on_signal();
	test_event();
	test_setup_uffd();
	return 0;
}
