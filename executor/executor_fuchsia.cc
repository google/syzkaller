// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build

#define SYZ_EXECUTOR
#include "common_fuchsia.h"

struct event_t {
	pthread_mutex_t mu;
	pthread_cond_t cv;
	bool state;
};

#include "executor.h"

#include "syscalls_fuchsia.h"

char input_data[kMaxInput];
uint32_t output;

int main(int argc, char** argv)
{
	if (argc == 2 && strcmp(argv[1], "version") == 0) {
		puts("linux " GOARCH " " SYZ_REVISION " " GIT_REVISION);
		return 0;
	}

	int pos = 0;
	for (;;) {
		int rv = read(0, input_data + pos, sizeof(input_data) - pos);
		if (rv < 0)
			fail("read failed");
		if (rv == 0)
			break;
		pos += rv;
	}
	if (pos < 24)
		fail("truncated input");

	uint64_t flags = *(uint64_t*)input_data;
	flag_debug = flags & (1 << 0);
	flag_threaded = flags & (1 << 2);
	flag_collide = flags & (1 << 3);
	if (!flag_threaded)
		flag_collide = false;
	uint64_t executor_pid = *((uint64_t*)input_data + 2);
	debug("input %d, threaded=%d collide=%d pid=%llu\n",
	      pos, flag_threaded, flag_collide, executor_pid);

	execute_one(((uint64_t*)input_data) + 3);
	return 0;
}

long execute_syscall(call_t* c, long a0, long a1, long a2, long a3, long a4, long a5, long a6, long a7, long a8)
{
	debug("%s = %p\n", c->name, c->call);
	long res = c->call(a0, a1, a2, a3, a4, a5, a6, a7, a8);
	debug("%s = %ld\n", c->name, res);
	return res;
}

void cover_open()
{
}

void cover_enable(thread_t* th)
{
}

void cover_reset(thread_t* th)
{
}

uint64_t read_cover_size(thread_t* th)
{
	return 0;
}

uint32_t* write_output(uint32_t v)
{
	return &output;
}

void write_completed(uint32_t completed)
{
}

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
