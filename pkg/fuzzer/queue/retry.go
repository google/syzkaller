// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package queue

import (
	"fmt"
)

type retryer struct {
	pq   *PlainQueue
	base Source
}

// Retry adds a layer that resends results with Status=Restarted.
func Retry(base Source) Source {
	return &retryer{
		base: base,
		pq:   Plain(),
	}
}

func (r *retryer) Next() *Request {
	req := r.pq.tryNext()
	if req == nil {
		req = r.base.Next()
	}
	if req != nil {
		req.OnDone(r.done)
	}
	return req
}

func (r *retryer) done(req *Request, res *Result) bool {
	switch res.Status {
	case Success, ExecFailure, Hanged:
		return true
	case Restarted:
		// The input was on a restarted VM.
		r.pq.Submit(req)
		return false
	case Crashed:
		// Retry important requests from crashed VMs once.
		if req.Important && !req.onceCrashed {
			req.onceCrashed = true
			r.pq.Submit(req)
			return false
		}
		return true
	default:
		panic(fmt.Sprintf("unhandled status %v", res.Status))
	}
}
