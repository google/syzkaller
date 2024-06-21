// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package throttler

import (
	"math/rand"
	"testing"

	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/testutil"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
	"github.com/google/syzkaller/sys/targets"
	"github.com/stretchr/testify/assert"
)

func TestThrottler(t *testing.T) {
	target, err := prog.GetTarget(targets.TestOS, targets.TestArch64)
	if err != nil {
		t.Fatal(err)
	}

	rs := testutil.RandSource(t)

	var calls []*prog.Syscall
	bad := map[*prog.Syscall]bool{}
	for i, call := range target.Syscalls {
		calls = append(calls, call)
		if i <= 2 {
			bad[call] = true
		}
		if i == 40 {
			break
		}
	}

	rnd := rand.New(rs)

	// Generate random progs.
	limit := 100000
	base := queue.Callback(func() *queue.Request {
		limit--
		if limit < 0 {
			return nil
		}
		return &queue.Request{
			Prog: &prog.Prog{
				Calls: []*prog.Call{
					{
						Meta: calls[rnd.Intn(len(calls))],
					},
				},
			},
		}
	})

	wrapper := Wrapper(base, calls)
	crashes := 0
outer:
	for {
		monitor := wrapper.InstanceMonitor()
		crashIn := 10000
		count := 0
		for {
			count++
			req := wrapper.Next()
			if req == nil {
				break outer
			}
			monitor.Record(req)
			if crashIn == 0 {
				monitor.Shutdown(true)
				crashes++
				t.Logf("crashed after %d progs", count)
				break
			}
			crashIn--
			call := req.Prog.Calls[0]
			// Fail bad calls with a 33% probability, but delay it.
			if !call.Props.Skip && bad[call.Meta] && rnd.Intn(3) == 0 {
				crashIn = min(crashIn, rnd.Intn(10))
			}
		}
	}

	t.Logf("total crashes: %v", crashes)
	t.Logf("total risky calls run: %v", wrapper.statRiskyExecs.Val())
	totalDenied := wrapper.statDeniedExecs.Val()
	t.Logf("total denied calls: %v", totalDenied)

	var badDenials int64
	for _, call := range calls {
		info := wrapper.Info(call)
		typ := "good"
		if bad[call] {
			typ = "bad"
			badDenials += info.Denied
		}
		if info.Throttled {
			typ += " [IN POLICY]"
		}
		assert.Equal(t, bad[call], info.Throttled, "all & only bad calls must be throttled")
		t.Logf("[%d] %s call %s: %d crashed (%.2f%%), %d denied",
			call.ID, typ, call.Name, info.Crashed,
			info.CrashRate*100.0, info.Denied)
	}

	// There can be 100000*(1/3)*(3/40) > 2.5k crashes if the algorithm did not work.
	// Let's consider it a success if it finished with less than 333.
	assert.Less(t, crashes, 333)

	// Also, demand that >2/3 of all execution denials happened on the 3 bad calls.
	assert.Greater(t, badDenials, int64(totalDenied*2/3))
}
