// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package queue

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRetryerOnRestart(t *testing.T) {
	q := Plain()
	retryerObj := Retry(q)

	q.Submit(&Request{Important: true})
	q.Submit(&Request{Important: false})

	// The requests must be retried forever.
	req1, stop := retryerObj.Next()
	assert.False(t, stop)
	req2, stop := retryerObj.Next()
	assert.False(t, stop)
	for i := 0; i < 10; i++ {
		req1.Done(&Result{Status: Restarted})
		req2.Done(&Result{Status: Restarted})
		req, stop := retryerObj.Next()
		assert.Equal(t, req1, req)
		assert.False(t, stop)
		req, stop = retryerObj.Next()
		assert.Equal(t, req2, req)
		assert.False(t, stop)
	}

	// Once successful, requests should no longer appear.
	req1.Done(&Result{Status: Success})
	req2.Done(&Result{Status: Success})

	assert.Equal(t, Success, req1.Wait(context.Background()).Status)
	assert.Equal(t, Success, req2.Wait(context.Background()).Status)

	req, _ := retryerObj.Next()
	assert.Nil(t, req)
}

func TestRetryerOnCrash(t *testing.T) {
	q := Plain()
	retryerObj := Retry(q)

	// Unimportant requests will not be retried.
	req := &Request{Important: false}
	q.Submit(req)
	nextReq, _ := retryerObj.Next()
	assert.Equal(t, req, nextReq)
	req.Done(&Result{Status: Crashed})
	nextReq, _ = retryerObj.Next()
	assert.Nil(t, nextReq)
	assert.Equal(t, Crashed, req.Wait(context.Background()).Status)

	// Important requests will be retried once.
	req = &Request{Important: true}
	q.Submit(req)
	nextReq, _ = retryerObj.Next()
	assert.Equal(t, req, nextReq)
	req.Done(&Result{Status: Crashed})
	nextReq, _ = retryerObj.Next()
	assert.Equal(t, req, nextReq)
	req.Done(&Result{Status: Success})
	nextReq, _ = retryerObj.Next()
	assert.Nil(t, nextReq)
	assert.Equal(t, Success, req.Wait(context.Background()).Status)

	// .. but not more than once.
	req = &Request{Important: true}
	q.Submit(req)
	nextReq, _ = retryerObj.Next()
	assert.Equal(t, req, nextReq)
	req.Done(&Result{Status: Crashed})
	nextReq, _ = retryerObj.Next()
	assert.Equal(t, req, nextReq)
	req.Done(&Result{Status: Crashed})
	nextReq, _ = retryerObj.Next()
	assert.Nil(t, nextReq)
	assert.Equal(t, Crashed, req.Wait(context.Background()).Status)
}
