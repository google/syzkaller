// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package pages

import (
	"io"
	"testing"

	"github.com/google/syzkaller/pkg/stat"
)

func TestStatsTemplate(t *testing.T) {
	if err := StatsTemplate.Execute(io.Discard, stat.RenderGraphs()); err != nil {
		t.Fatal(err)
	}
}
