// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"testing"
)

func TestLoadConfig(t *testing.T) {
	if _, err := loadConfig("testdata/example.cfg"); err != nil {
		t.Fatalf("failed to load: %v", err)
	}
}
