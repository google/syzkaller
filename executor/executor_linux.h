// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#include <pthread.h>

typedef pthread_t osthread_t;

void thread_start(osthread_t* t, void* (*fn)(void*), void* arg)
{
	pthread_attr_t attr;
	pthread_attr_init(&attr);
	pthread_attr_setstacksize(&attr, 128 << 10);
	if (pthread_create(t, &attr, fn, arg))
		exitf("pthread_create failed");
	pthread_attr_destroy(&attr);
}

struct event_t {
	int state;
};

void event_init(event_t* ev)
{
	ev->state = 0;
}

void event_reset(event_t* ev)
{
	ev->state = 0;
}

void event_set(event_t* ev)
{
	if (ev->state)
		fail("event already set");
	__atomic_store_n(&ev->state, 1, __ATOMIC_RELEASE);
	syscall(SYS_futex, &ev->state, FUTEX_WAKE);
}

void event_wait(event_t* ev)
{
	while (!__atomic_load_n(&ev->state, __ATOMIC_ACQUIRE))
		syscall(SYS_futex, &ev->state, FUTEX_WAIT, 0, 0);
}

bool event_isset(event_t* ev)
{
	return __atomic_load_n(&ev->state, __ATOMIC_ACQUIRE);
}

bool event_timedwait(event_t* ev, uint64 timeout_ms)
{
	uint64 start = current_time_ms();
	uint64 now = start;
	for (;;) {
		timespec ts = {};
		ts.tv_sec = 0;
		ts.tv_nsec = (timeout_ms - (now - start)) * 1000 * 1000;
		syscall(SYS_futex, &ev->state, FUTEX_WAIT, 0, &ts);
		if (__atomic_load_n(&ev->state, __ATOMIC_RELAXED))
			return true;
		now = current_time_ms();
		if (now - start > timeout_ms)
			return false;
	}
}
