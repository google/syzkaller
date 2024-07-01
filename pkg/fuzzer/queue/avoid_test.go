// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package queue

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestAvoid(t *testing.T) {
	q := Plain()
	avoid := Avoid(q)

	req := &Request{}
	q.Submit(req)
	assert.Equal(t, req, avoid.Next(0))

	q.Submit(req)
	assert.Equal(t, req, avoid.Next(1))

	// Avoid VM 0.
	req.Avoid = []ExecutorID{{VM: 0}}
	q.Submit(req)
	var noReq *Request
	assert.Equal(t, noReq, avoid.Next(0))
	assert.Equal(t, noReq, avoid.Next(0))
	assert.Equal(t, req, avoid.Next(1))

	// If only VM 0 queries requests, it should eventually got it.
	q.Submit(req)
	assert.Equal(t, noReq, avoid.Next(0))
	for {
		got := avoid.Next(0)
		if got == req {
			break
		}
		assert.Equal(t, noReq, got)
	}

	// If all active VMs are in the avoid set, then they should get
	// the request immidiatly.
	assert.Equal(t, noReq, avoid.Next(1))
	req.Avoid = []ExecutorID{{VM: 0}, {VM: 1}}
	q.Submit(req)
	assert.Equal(t, req, avoid.Next(1))
}
