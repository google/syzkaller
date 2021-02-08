// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package host

import (
	"strings"
	"testing"
)

func TestRequireKernel(t *testing.T) {
	if what := requireKernel(2, 999); what != "" {
		t.Fatalf("requireKernel(2, 999) failed: %v", what)
	}
	if what := requireKernel(3, 0); what != "" {
		t.Fatalf("requireKernel(3, 0) failed: %v", what)
	}
	if what := requireKernel(99, 1); what == "" {
		t.Fatalf("requireKernel(99, 1) succeeded")
	} else if !strings.HasPrefix(what, "kernel 99.1 required") {
		t.Fatalf("requireKernel(99, 1) failed: %v", what)
	}
}
