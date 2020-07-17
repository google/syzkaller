// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"strings"
	"testing"
)

func TestResourceCtors(t *testing.T) {
	if testing.Short() && raceEnabled {
		t.Skip("too slow")
	}
	testEachTarget(t, func(t *testing.T, target *Target) {
		for _, res := range target.Resources {
			if len(target.calcResourceCtors(res, true)) == 0 && !strings.HasPrefix(res.Name, "ANY") {
				t.Errorf("resource %v can't be created", res.Name)
			}
		}
	})
}

func TestTransitivelyEnabledCalls(t *testing.T) {
	testEachTarget(t, func(t *testing.T, target *Target) {
		calls := make(map[*Syscall]bool)
		for _, c := range target.Syscalls {
			calls[c] = true
		}
		enabled, disabled := target.TransitivelyEnabledCalls(calls)
		for c, ok := range enabled {
			if !ok {
				t.Fatalf("syscalls %v is false in enabled map", c.Name)
			}
		}
		if target.OS == "test" {
			for c := range enabled {
				if c.CallName == "unsupported" {
					t.Errorf("call %v is not disabled", c.Name)
				}
			}
			for c, reason := range disabled {
				if c.CallName != "unsupported" {
					t.Errorf("call %v is disabled: %v", c.Name, reason)
				}
			}
		} else {
			if len(enabled) != len(target.Syscalls) {
				t.Errorf("some calls are disabled: %v/%v", len(enabled), len(target.Syscalls))
			}
			if len(disabled) != 0 {
				for c, reason := range disabled {
					t.Errorf("disabled %v: %v", c.Name, reason)
				}
			}
		}
	})
}

func TestTransitivelyEnabledCallsLinux(t *testing.T) {
	t.Parallel()
	target, err := GetTarget("linux", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	calls := make(map[*Syscall]bool)
	for _, c := range target.Syscalls {
		calls[c] = true
	}
	delete(calls, target.SyscallMap["epoll_create"])
	if trans, disabled := target.TransitivelyEnabledCalls(calls); len(disabled) != 0 || len(trans) != len(calls) {
		t.Fatalf("still must be able to create epoll fd with epoll_create1")
	}
	delete(calls, target.SyscallMap["epoll_create1"])
	trans, disabled := target.TransitivelyEnabledCalls(calls)
	if len(calls)-7 != len(trans) ||
		trans[target.SyscallMap["epoll_ctl$EPOLL_CTL_ADD"]] ||
		trans[target.SyscallMap["epoll_ctl$EPOLL_CTL_MOD"]] ||
		trans[target.SyscallMap["epoll_ctl$EPOLL_CTL_DEL"]] ||
		trans[target.SyscallMap["epoll_wait"]] ||
		trans[target.SyscallMap["epoll_pwait"]] ||
		trans[target.SyscallMap["kcmp$KCMP_EPOLL_TFD"]] ||
		trans[target.SyscallMap["syz_io_uring_submit$IORING_OP_EPOLL_CTL"]] {
		t.Fatalf("epoll fd is not disabled")
	}
	if len(disabled) != 7 {
		t.Fatalf("disabled %v syscalls, want 7", len(disabled))
	}
	for c, reason := range disabled {
		if !strings.Contains(reason, "no syscalls can create resource fd_epoll,"+
			" enable some syscalls that can create it [epoll_create epoll_create1]") {
			t.Fatalf("%v: wrong disable reason: %v", c.Name, reason)
		}
	}
}

func TestClockGettime(t *testing.T) {
	t.Parallel()
	target, err := GetTarget("linux", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	calls := make(map[*Syscall]bool)
	for _, c := range target.Syscalls {
		calls[c] = true
	}
	// Removal of clock_gettime should disable all calls that accept timespec/timeval.
	delete(calls, target.SyscallMap["clock_gettime"])
	trans, disabled := target.TransitivelyEnabledCalls(calls)
	if len(trans)+10 > len(calls) || len(trans)+len(disabled) != len(calls) || len(trans) == 0 {
		t.Fatalf("clock_gettime did not disable enough calls: before %v, after %v, disabled %v",
			len(calls), len(trans), len(disabled))
	}
}
