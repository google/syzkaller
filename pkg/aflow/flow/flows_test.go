// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package flow

import (
	"testing"

	"github.com/google/syzkaller/pkg/aflow"
)

// Note: this test also runs registration and verification of all registered workflows via init functions.

func TestMCPTools(t *testing.T) {
	for tool := range aflow.MCPTools {
		t.Log(tool.Name)
	}
}
