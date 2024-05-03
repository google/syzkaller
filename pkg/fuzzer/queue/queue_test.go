// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package queue

import (
	"testing"

	"github.com/google/syzkaller/pkg/stats"
	"github.com/stretchr/testify/assert"
)

func TestPlainQueue(t *testing.T) {
	val := stats.Create("v0", "desc0")
	pq := PlainWithStat(val)

	req1, req2, req3 := &Request{}, &Request{}, &Request{}

	pq.Submit(req1)
	assert.Equal(t, 1, val.Val())
	pq.Submit(req2)
	assert.Equal(t, 2, val.Val())

	assert.Equal(t, req1, pq.Next())
	assert.Equal(t, 1, val.Val())

	assert.Equal(t, req2, pq.Next())
	assert.Equal(t, 0, val.Val())

	pq.Submit(req3)
	assert.Equal(t, 1, val.Val())
	assert.Equal(t, req3, pq.Next())
	assert.Nil(t, pq.Next())
}

func TestPrioQueue(t *testing.T) {
	req1, req2, req3, req4 :=
		&Request{}, &Request{}, &Request{}, &Request{}
	pq := Priority()

	pq1 := pq.AppendQueue()
	pq2 := pq.AppendQueue()
	pq3 := pq.AppendQueue()

	pq2.Submit(req2)
	pq3.Submit(req3)
	pq3.Submit(req4)
	pq1.Submit(req1)

	assert.Equal(t, req1, pq.Next())
	assert.Equal(t, req2, pq.Next())
	assert.Equal(t, req3, pq.Next())
	assert.Equal(t, req4, pq.Next())
}
