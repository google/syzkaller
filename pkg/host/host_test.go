// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package host

import (
	"runtime"
	"testing"

	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

func TestLog(t *testing.T) {
	t.Parallel()
	target, err := prog.GetTarget(runtime.GOOS, runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}
	// Dump for manual inspection.
	supp, disabled, err := DetectSupportedSyscalls(target, "none")
	if err != nil {
		t.Skipf("skipping: %v", err)
	}
	for c, ok := range supp {
		if !ok {
			t.Fatalf("map contains false value for %v", c.Name)
		}
	}
	t.Logf("unsupported:")
	for c, reason := range disabled {
		t.Logf("%v: %v", c.Name, reason)
	}
	_, disabled = target.TransitivelyEnabledCalls(supp)
	t.Logf("\n\ntransitively unsupported:")
	for c, reason := range disabled {
		t.Logf("%v: %v", c.Name, reason)
	}
}
