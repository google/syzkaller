// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"testing"

	"github.com/google/syzkaller/pkg/html"
)

func TestTemplatesCompile(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("template parsing panicked: %v", r)
		}
	}()
	html.CreateGlob("*.html")
}
