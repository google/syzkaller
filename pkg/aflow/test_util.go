// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// NewTestContext creates an initialized dummy Context for internal aflow and tool unit tests.
func NewTestContext(t *testing.T) *Context {
	cache, err := NewCache(t.TempDir(), 10000000)
	require.NoError(t, err)

	return &Context{
		cache: cache,
	}
}
