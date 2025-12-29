// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAIMigrations(t *testing.T) {
	// Ensure spanner DDL files are syntax-correct and idempotent.
	// NewSpannerCtx already run the "up" statements, so we start with "down".
	c := NewSpannerCtx(t)
	defer c.Close()

	up, err := loadDDLStatements("1_initialize.up.sql")
	require.NoError(t, err)
	down, err := loadDDLStatements("1_initialize.down.sql")
	require.NoError(t, err)

	require.NoError(t, executeSpannerDDL(c.ctx, down))
	require.NoError(t, executeSpannerDDL(c.ctx, up))
	require.NoError(t, executeSpannerDDL(c.ctx, down))
}
