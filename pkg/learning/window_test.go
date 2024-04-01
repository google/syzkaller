// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package learning

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRunningRatioAverage(t *testing.T) {
	ra := NewRunningRatioAverage[float64](3)
	for i := 0; i < 4; i++ {
		ra.Save(2.0, 1.0)
	}
	assert.InDelta(t, 2.0, ra.Load(), 0.1)
	for i := 0; i < 4; i++ {
		ra.Save(3.0, 2.0)
	}
	assert.InDelta(t, 1.5, ra.Load(), 0.1)
}

func TestRunningAverage(t *testing.T) {
	ra := NewRunningAverage[int](3)
	assert.Equal(t, 0, ra.Load())
	ra.Save(1)
	assert.Equal(t, 1, ra.Load())
	ra.Save(2)
	assert.Equal(t, 3, ra.Load())
	for i := 4; i <= 10; i++ {
		ra.SaveInt(i)
	}
	assert.Equal(t, 8+9+10, ra.Load())
}
