// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package host

import (
	"fmt"
	"runtime"
	"testing"

	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

func TestDetectSupportedSyscalls(t *testing.T) {
	// Note: this test is not parallel because it modifies global testFallback var.
	for _, fallback := range []bool{false, true} {
		t.Run(fmt.Sprintf("fallback=%v", fallback), func(t *testing.T) {
			oldFallback := testFallback
			testFallback = fallback
			defer func() { testFallback = oldFallback }()
			target, err := prog.GetTarget(runtime.GOOS, runtime.GOARCH)
			if err != nil {
				t.Fatal(err)
			}
			// Dump for manual inspection.
			supp, disabled, err := DetectSupportedSyscalls(target, "none")
			if err != nil {
				t.Fatal(err)
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
		})
	}
}

func TestCheck(t *testing.T) {
	t.Parallel()
	target, err := prog.GetTarget(runtime.GOOS, runtime.GOARCH)
	if err != nil {
		t.Fatal(err)
	}
	features, err := Check(target)
	if err != nil {
		t.Fatal(err)
	}
	for _, feat := range features.Supported() {
		t.Logf("%-24v: %v", feat.Name, feat.Reason)
	}
}
