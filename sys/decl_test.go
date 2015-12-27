// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sys

import (
	"testing"
)

func TestTransitivelyEnabledCalls(t *testing.T) {
	calls := make(map[*Call]bool)
	for _, c := range Calls {
		calls[c] = true
	}
	if trans := TransitivelyEnabledCalls(calls); len(calls) != len(trans) {
		for c := range calls {
			if !trans[c] {
				t.Logf("disabled %v", c.Name)
			}
		}
		t.Fatalf("can't create some resource")
	}
	delete(calls, CallMap["epoll_create"])
	if trans := TransitivelyEnabledCalls(calls); len(calls) != len(trans) {
		t.Fatalf("still must be able to create epoll fd with epoll_create1")
	}
	delete(calls, CallMap["epoll_create1"])
	trans := TransitivelyEnabledCalls(calls)
	if len(calls)-3 != len(trans) ||
		trans[CallMap["epoll_ctl"]] ||
		trans[CallMap["epoll_wait"]] ||
		trans[CallMap["epoll_pwait"]] {
		t.Fatalf("epoll fd is not disabled")
	}
}
