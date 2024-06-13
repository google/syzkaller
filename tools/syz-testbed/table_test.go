// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"testing"

	"github.com/google/syzkaller/pkg/stats/sample"
	"github.com/stretchr/testify/assert"
)

func TestRelativeValues(t *testing.T) {
	table := NewTable("", "A", "B")
	table.Set("row1", "A", NewValueCell(&sample.Sample{Xs: []float64{2, 2}}))
	table.Set("row1", "B", NewValueCell(&sample.Sample{Xs: []float64{3, 3}}))
	// Don't set row2/A.
	table.Set("row2", "B", NewValueCell(&sample.Sample{Xs: []float64{1, 1}}))

	err := table.SetRelativeValues("A")
	assert.NoError(t, err)

	assert.InDelta(t, 50.0, *table.Get("row1", "B").(*ValueCell).PercentChange, 0.1)
	assert.Nil(t, table.Get("row1", "A").(*ValueCell).PercentChange)
	assert.Nil(t, table.Get("row2", "A"))
	assert.Nil(t, table.Get("row2", "B").(*ValueCell).PercentChange)
}
