// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package signal

import (
	"math/rand"
	"testing"

	"github.com/google/syzkaller/pkg/testutil"
	"github.com/stretchr/testify/assert"
)

func TestRandomSubset(t *testing.T) {
	r := rand.New(testutil.RandSource(t))
	base := FromRaw([]uint32{0, 1, 2, 3, 4}, 0)
	var s Signal
	for i := 0; i < 1000 && s.Len() < base.Len(); i++ {
		delta := base.RandomSubset(r, 1)
		assert.Equal(t, 1, delta.Len())
		s.Merge(delta)
	}
	assert.Equal(t, base.Len(), s.Len())
}

func TestSubtract(t *testing.T) {
	base := FromRaw([]uint32{0, 1, 2, 3, 4}, 0)
	assert.Equal(t, 5, base.Len())
	base.Subtract(FromRaw([]uint32{0}, 0))
	assert.Equal(t, 4, base.Len())
	base.Subtract(FromRaw([]uint32{1}, 0))
	assert.Equal(t, 3, base.Len())
}
