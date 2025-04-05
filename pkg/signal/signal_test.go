// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package signal

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIntersectsWith(t *testing.T) {
	base := FromRaw([]uint64{0, 1, 2, 3, 4}, 1)
	assert.True(t, base.IntersectsWith(FromRaw([]uint64{0, 5, 10}, 1)))
	assert.False(t, base.IntersectsWith(FromRaw([]uint64{5, 10, 15}, 1)))
	// The other signal has a lower priority.
	assert.False(t, base.IntersectsWith(FromRaw([]uint64{0, 1, 2}, 0)))
}
