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
	req1 := retryerObj.Next()
	req2 := retryerObj.Next()
	for i := 0; i < 10; i++ {
		req1.Done(&Result{Status: Restarted})
		req2.Done(&Result{Status: Restarted})
		assert.Equal(t, req1, retryerObj.Next())
		assert.Equal(t, req2, retryerObj.Next())
	}

	// Once successful, requests should no longer appear.
	req1.Done(&Result{Status: Success})
	req2.Done(&Result{Status: Success})

	assert.Equal(t, Success, req1.Wait(context.Background()).Status)
	assert.Equal(t, Success, req2.Wait(context.Background()).Status)

	assert.Nil(t, retryerObj.Next())
	assert.Nil(t, retryerObj.Next())
}

func TestRetryerOnCrash(t *testing.T) {
	q := Plain()
	retryerObj := Retry(q)

	// Unimportant requests will not be retried.
	req := &Request{Important: false}
	q.Submit(req)
	assert.Equal(t, req, retryerObj.Next())
	req.Done(&Result{Status: Crashed})
	assert.Nil(t, retryerObj.Next())
	assert.Equal(t, Crashed, req.Wait(context.Background()).Status)

	// Important requests will be retried once.
	req = &Request{Important: true}
	q.Submit(req)
	assert.Equal(t, req, retryerObj.Next())
	req.Done(&Result{Status: Crashed})
	assert.Equal(t, req, retryerObj.Next())
	req.Done(&Result{Status: Success})
	assert.Nil(t, retryerObj.Next())
	assert.Equal(t, Success, req.Wait(context.Background()).Status)

	// .. but not more than once.
	req = &Request{Important: true}
	q.Submit(req)
	assert.Equal(t, req, retryerObj.Next())
	req.Done(&Result{Status: Crashed})
	assert.Equal(t, req, retryerObj.Next())
	req.Done(&Result{Status: Crashed})
	assert.Nil(t, retryerObj.Next())
	assert.Equal(t, Crashed, req.Wait(context.Background()).Status)
}
