// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestFullCombinations(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		assert.Len(t, CoveringArray([][]string{}, 0), 0)
	})
	t.Run("single", func(t *testing.T) {
		assert.Equal(t, [][]string{
			{"A", "B", "C"},
		}, CoveringArray([][]string{
			{"A"},
			{"B"},
			{"C"},
		}, 0))
	})
	t.Run("binary", func(t *testing.T) {
		assert.Equal(t, [][]string{
			{"A", "B", "C"},
			{"A", "B", "c"},
			{"A", "b", "C"},
			{"A", "b", "c"},
			{"a", "B", "C"},
			{"a", "B", "c"},
			{"a", "b", "C"},
			{"a", "b", "c"},
		}, CoveringArray([][]string{
			{"A", "a"},
			{"B", "b"},
			{"C", "c"},
		}, 0))
	})
}

func TestPairCombinations(t *testing.T) {
	// Theoretically, there may be multiple correct answers.
	// For now, let's keep the current algorithm's output so that if the code behavior changes unexpectedly,
	// we'd notice.
	assert.Equal(t, [][]string{
		{"A", "B", "C"},
		{"A", "b", "c"},
		{"a", "B", "c"},
		{"a", "b", "C"},
	}, CoveringArray([][]string{
		{"A", "a"},
		{"B", "b"},
		{"C", "c"},
	}, 4))
}
