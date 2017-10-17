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
	pthread_mutex_t mu;
	pthread_cond_t cv;
	bool state;
};

void event_init(event_t* ev)
{
	if (pthread_mutex_init(&ev->mu, 0))
		fail("pthread_mutex_init failed");
	if (pthread_cond_init(&ev->cv, 0))
		fail("pthread_cond_init failed");
	ev->state = false;
}

void event_reset(event_t* ev)
{
	ev->state = false;
}

void event_set(event_t* ev)
{
	pthread_mutex_lock(&ev->mu);
	if (ev->state)
		fail("event already set");
	ev->state = true;
	pthread_mutex_unlock(&ev->mu);
	pthread_cond_broadcast(&ev->cv);
}

void event_wait(event_t* ev)
{
	pthread_mutex_lock(&ev->mu);
	while (!ev->state)
		pthread_cond_wait(&ev->cv, &ev->mu);
	pthread_mutex_unlock(&ev->mu);
}

bool event_isset(event_t* ev)
{
	pthread_mutex_lock(&ev->mu);
	bool res = ev->state;
	pthread_mutex_unlock(&ev->mu);
	return res;
}

bool event_timedwait(event_t* ev, uint64_t timeout_ms)
{
	pthread_mutex_lock(&ev->mu);
	uint64_t start = current_time_ms();
	for (;;) {
		if (ev->state)
			break;
		uint64_t now = current_time_ms();
		if (now - start > timeout_ms)
			break;
		timespec ts;
		ts.tv_sec = 0;
		ts.tv_nsec = (timeout_ms - (now - start)) * 1000 * 1000;
		pthread_cond_timedwait(&ev->cv, &ev->mu, &ts);
	}
	bool res = ev->state;
	pthread_mutex_unlock(&ev->mu);
	return res;
}
