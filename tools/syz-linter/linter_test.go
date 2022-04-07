// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"testing"

	"github.com/google/syzkaller/pkg/osutil"
	"golang.org/x/tools/go/analysis/analysistest"
)

func TestLinter(t *testing.T) {
	analysistest.Run(t, osutil.Abs("testdata"), SyzAnalyzer, "lintertest")
}
