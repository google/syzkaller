// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package queue

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPlainQueue(t *testing.T) {
	pq := Plain()

	req1, req2, req3 := &Request{}, &Request{}, &Request{}

	pq.Submit(req1)
	pq.Submit(req2)

	val, stop := pq.Next()
	assert.Equal(t, req1, val)
	assert.False(t, stop)

	val, stop = pq.Next()
	assert.Equal(t, req2, val)
	assert.False(t, stop)
	pq.Submit(req3)

	val, stop = pq.Next()
	assert.Equal(t, req3, val)
	assert.False(t, stop)

	val, stop = pq.Next()
	assert.Nil(t, val)
	assert.False(t, stop)
}

func TestPrioQueue(t *testing.T) {
	req1, req2, req3, req4 :=
		&Request{}, &Request{}, &Request{}, &Request{}
	pq := DynamicOrder()

	pq1 := pq.Append()
	pq2 := pq.Append()
	pq3 := pq.Append()

	pq2.Submit(req2)
	pq3.Submit(req3)

	val, stop := pq.Next()
	assert.Equal(t, req2, val)
	assert.False(t, stop)

	pq1.Submit(req1)
	val, stop = pq.Next()
	assert.Equal(t, req1, val)
	assert.False(t, stop)

	pq2.Submit(req4)
	val, stop = pq.Next()
	assert.Equal(t, req4, val)
	assert.False(t, stop)

	val, stop = pq.Next()
	assert.Equal(t, req3, val)
	assert.False(t, stop)
}
