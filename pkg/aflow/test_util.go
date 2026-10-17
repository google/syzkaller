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
		Context: t.Context(),
		cache:   cache,
		logf: func(_ int, msg string, args ...any) {
			t.Logf(msg, args...)
		},
	}
}

// TestFormatTemplate renders an agent prompt/instruction template with the given state.
// Template verification during flow registration executes templates only with zero values,
// so this allows to test templates that e.g. range over non-empty slices.
func TestFormatTemplate(t *testing.T, text string, state map[string]any) string {
	t.Helper()
	var res string
	require.NotPanics(t, func() { res = formatTemplate(text, state) })
	return res
}
