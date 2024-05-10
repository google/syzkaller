// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"math/rand"
	"strings"
	"testing"

	"github.com/google/syzkaller/pkg/testutil"
	"github.com/stretchr/testify/assert"
)

func TestResourceCtors(t *testing.T) {
	if testing.Short() && testutil.RaceEnabled {
		t.Skip("too slow")
	}
	testEachTarget(t, func(t *testing.T, target *Target) {
		for _, res := range target.Resources {
			if len(target.calcResourceCtors(res, true)) == 0 && !strings.HasPrefix(res.Name, "ANY") &&
				res.Name != "disabled_resource" {
				t.Errorf("resource %v can't be created", res.Name)
			}
		}
	})
}

func TestTransitivelyEnabledCalls(t *testing.T) {
	testEachTarget(t, func(t *testing.T, target *Target) {
		calls := make(map[*Syscall]bool)
		for _, c := range target.Syscalls {
			if c.Attrs.Disabled {
				continue
			}
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
			if len(enabled) != len(calls) {
				t.Errorf("some calls are disabled: %v/%v", len(enabled), len(calls))
			}
			for c, reason := range disabled {
				t.Errorf("disabled %v: %v", c.Name, reason)
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
		if c.Attrs.Disabled {
			continue
		}
		calls[c] = true
	}
	delete(calls, target.SyscallMap["epoll_create"])
	if trans, disabled := target.TransitivelyEnabledCalls(calls); len(disabled) != 0 || len(trans) != len(calls) {
		t.Fatalf("still must be able to create epoll fd with epoll_create1")
	}
	delete(calls, target.SyscallMap["epoll_create1"])
	trans, disabled := target.TransitivelyEnabledCalls(calls)
	if len(calls)-8 != len(trans) ||
		trans[target.SyscallMap["epoll_ctl$EPOLL_CTL_ADD"]] ||
		trans[target.SyscallMap["epoll_ctl$EPOLL_CTL_MOD"]] ||
		trans[target.SyscallMap["epoll_ctl$EPOLL_CTL_DEL"]] ||
		trans[target.SyscallMap["epoll_wait"]] ||
		trans[target.SyscallMap["epoll_pwait"]] ||
		trans[target.SyscallMap["epoll_pwait2"]] ||
		trans[target.SyscallMap["kcmp$KCMP_EPOLL_TFD"]] ||
		trans[target.SyscallMap["syz_io_uring_submit$IORING_OP_EPOLL_CTL"]] {
		t.Fatalf("epoll fd is not disabled")
	}
	if len(disabled) != 8 {
		t.Fatalf("disabled %v syscalls, want 8", len(disabled))
	}
	for c, reason := range disabled {
		if !strings.Contains(reason, "fd_epoll [epoll_create epoll_create1]") {
			t.Fatalf("%v: wrong disable reason: %v", c.Name, reason)
		}
	}
}

func TestGetInputResources(t *testing.T) {
	expectedRequiredResources := map[string]bool{
		"required_res1": false,
		"required_res2": false,
	}

	t.Parallel()
	target, err := GetTarget("test", "64")
	if err != nil {
		t.Fatal(err)
	}

	resources := target.getInputResources(target.SyscallMap["test$optional_res"])
	for _, resource := range resources {
		if _, ok := expectedRequiredResources[resource.Name]; ok {
			expectedRequiredResources[resource.Name] = true
		} else {
			t.Fatalf(" unexpected %v", resource.Name)
		}
	}
	for expectedRes, found := range expectedRequiredResources {
		if !found {
			t.Fatalf(" missing %v", expectedRes)
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

func TestCreateResourceRotation(t *testing.T) {
	target, rs, _ := initTest(t)
	allCalls := make(map[*Syscall]bool)
	for _, call := range target.Syscalls {
		allCalls[call] = true
	}
	rotator := MakeRotator(target, allCalls, rand.New(rs))
	testCreateResource(t, target, rotator.Select(), rs)
}

func TestCreateResourceHalf(t *testing.T) {
	target, rs, _ := initTest(t)
	r := rand.New(rs)
	var halfCalls map[*Syscall]bool
	for len(halfCalls) == 0 {
		halfCalls = make(map[*Syscall]bool)
		for _, call := range target.Syscalls {
			if r.Intn(10) == 0 {
				halfCalls[call] = true
			}
		}
		halfCalls, _ = target.TransitivelyEnabledCalls(halfCalls)
	}
	testCreateResource(t, target, halfCalls, rs)
}

func testCreateResource(t *testing.T, target *Target, calls map[*Syscall]bool, rs rand.Source) {
	r := newRand(target, rs)
	r.inGenerateResource = true
	ct := target.BuildChoiceTable(nil, calls)
	for call := range calls {
		if call.Attrs.Disabled {
			continue
		}
		t.Logf("testing call %v", call.Name)
		ForeachCallType(call, func(typ Type, ctx *TypeCtx) {
			if res, ok := typ.(*ResourceType); ok && ctx.Dir != DirOut {
				s := newState(target, ct, nil)
				arg, calls := r.createResource(s, res, DirIn)
				if arg == nil && !ctx.Optional {
					t.Fatalf("failed to create resource %v", res.Name())
				}
				if arg != nil && len(calls) == 0 {
					t.Fatalf("created resource %v, but got no calls", res.Name())
				}
			}
		})
	}
}

func TestPreferPreciseResources(t *testing.T) {
	target, rs, _ := initRandomTargetTest(t, "test", "64")
	r := newRand(target, rs)
	counts := map[string]int{}
	for i := 0; i < 2000; i++ {
		s := newState(target, target.DefaultChoiceTable(), nil)
		calls := r.generateParticularCall(s,
			target.SyscallMap["test$consume_subtype_of_common"])
		for _, call := range calls {
			if call.Meta.Name == "test$consume_subtype_of_common" {
				continue
			}
			counts[call.Meta.Name]++
		}
	}
	assert.Greater(t, counts["test$produce_common"], 70)
	assert.Greater(t, counts["test$also_produce_common"], 70)
	assert.Greater(t, counts["test$produce_subtype_of_common"], 1000)
}
