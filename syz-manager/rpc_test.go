// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestQueue(t *testing.T) {
	var called []bool
	expectCalled := func(val int) func(*int) {
		pos := len(called)
		called = append(called, false)
		return func(usedVal *int) {
			called[pos] = val == *usedVal
		}
	}
	expectNoCall := func(_ *int) {
		t.Fatal("unexpected revoke")
	}
	intToPtr := func(v int) *int {
		return &v
	}

	q := newQueue[int](3)

	// First test simple operation -- we push and then fetch right away.
	for i := 0; i < 10; i++ {
		q.Add(intToPtr(10), expectNoCall)
		assert.Equal(t, 10, *q.Fetch())
	}

	// Let's overflow the queue.
	for i := 0; i <= 10; i++ {
		expect := expectNoCall
		if i >= 3 {
			expect = expectCalled(i - 3)
		}
		ii := i
		q.Add(&ii, expect)
	}

	// Ensure the queue works fine after overflow.
	assert.Equal(t, 8, *q.Fetch())
	q.Add(intToPtr(11), expectNoCall)
	assert.Equal(t, 9, *q.Fetch())
	q.Add(intToPtr(12), expectNoCall)
	assert.Equal(t, 10, *q.Fetch())
	assert.Equal(t, 11, *q.Fetch())
	assert.Equal(t, 12, *q.Fetch())
	assert.Nil(t, q.Fetch())

	for _, v := range called {
		assert.True(t, v)
	}
}
