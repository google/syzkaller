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

func TestHasAny(t *testing.T) {
	sig := FromRaw([]uint64{10, 20, 30}, 1)
	assert.True(t, sig.HasAny(map[uint64]struct{}{20: {}, 40: {}}))
	assert.False(t, sig.HasAny(map[uint64]struct{}{40: {}, 50: {}}))
	assert.False(t, sig.HasAny(nil))
}
