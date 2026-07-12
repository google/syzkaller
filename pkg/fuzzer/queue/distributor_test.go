// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package queue

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDistributor(t *testing.T) {
	q := Plain()
	dist := Distribute(q)

	req := &Request{}
	q.Submit(req)
	assert.Equal(t, req, dist.Next(0))

	q.Submit(req)
	assert.Equal(t, req, dist.Next(1))

	// Avoid VM 0.
	req.Avoid = []ExecutorID{{VM: 0}}
	q.Submit(req)
	var noReq *Request
	assert.Equal(t, noReq, dist.Next(0))
	assert.Equal(t, noReq, dist.Next(0))
	assert.Equal(t, req, dist.Next(1))

	// If only VM 0 queries requests, it should eventually got it.
	q.Submit(req)
	assert.Equal(t, noReq, dist.Next(0))
	for {
		got := dist.Next(0)
		if got == req {
			break
		}
		assert.Equal(t, noReq, got)
	}

	// If all active VMs are in the avoid set, then they should get
	// the request immidiatly.
	assert.Equal(t, noReq, dist.Next(1))
	req.Avoid = []ExecutorID{{VM: 0}, {VM: 1}}
	q.Submit(req)
	assert.Equal(t, req, dist.Next(1))
}

// TestDistributorSingleVM checks that on a single-VM setup a request that avoids
// the only VM is still dispatched to it immediately, rather than delayed forever.
// Regression test: unused (over-allocated) slots in the active slice used to count
// as recently active while seq was below the recency window, so hasOtherActive
// wrongly reported another active VM and starved the Avoid (triage) request.
func TestDistributorSingleVM(t *testing.T) {
	q := Plain()
	dist := Distribute(q)

	// VM 0 is the only VM that ever serves requests.
	req := &Request{Avoid: []ExecutorID{{VM: 0}}}
	q.Submit(req)
	// With only VM 0 active, avoidance is impossible, so it must get the request
	// right away without waiting out the recency window.
	assert.Equal(t, req, dist.Next(0))
}
