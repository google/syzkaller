// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

#include <windows.h>

typedef HANDLE osthread_t;

void thread_start(osthread_t* t, void* (*fn)(void*), void* arg)
{
	*t = CreateThread(NULL, 128 << 10, (LPTHREAD_START_ROUTINE)fn, arg, 0, NULL);
	if (*t == NULL)
		exitf("CreateThread failed");
}

struct event_t {
	CRITICAL_SECTION cs;
	CONDITION_VARIABLE cv;
	int state;
};

void event_init(event_t* ev)
{
	InitializeCriticalSection(&ev->cs);
	InitializeConditionVariable(&ev->cv);
	ev->state = 0;
}

void event_reset(event_t* ev)
{
	ev->state = 0;
}

void event_set(event_t* ev)
{
	EnterCriticalSection(&ev->cs);
	if (ev->state)
		fail("event already set");
	ev->state = true;
	LeaveCriticalSection(&ev->cs);
	WakeAllConditionVariable(&ev->cv);
}

void event_wait(event_t* ev)
{
	EnterCriticalSection(&ev->cs);
	while (!ev->state)
		SleepConditionVariableCS(&ev->cv, &ev->cs, INFINITE);
	LeaveCriticalSection(&ev->cs);
}

bool event_isset(event_t* ev)
{
	EnterCriticalSection(&ev->cs);
	bool res = ev->state;
	LeaveCriticalSection(&ev->cs);
	return res;
}

bool event_timedwait(event_t* ev, uint64 timeout_ms)
{
	EnterCriticalSection(&ev->cs);
	uint64 start = current_time_ms();
	for (;;) {
		if (ev->state)
			break;
		uint64 now = current_time_ms();
		if (now - start > timeout_ms)
			break;
		SleepConditionVariableCS(&ev->cv, &ev->cs, timeout_ms - (now - start));
	}
	bool res = ev->state;
	LeaveCriticalSection(&ev->cs);
	return res;
}
