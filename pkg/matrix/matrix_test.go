// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package matrix

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadMatrix(t *testing.T) {
	matrix, err := LoadMatrix("../../tools/syz-matrix/matrix.yaml")
	require.NoError(t, err)
	require.NotEmpty(t, matrix.Base.Features)
	require.Contains(t, matrix.Axes, "platform")
	require.Contains(t, matrix.Axes, "sanitizer")
	require.Contains(t, matrix.Axes, "preemption")
	require.Contains(t, matrix.Overlays, "lockdep")
	require.Contains(t, matrix.Overlays, "storage_filesystems")
}

func TestSampleFiltered(t *testing.T) {
	matrix, err := LoadMatrix("../../tools/syz-matrix/matrix.yaml")
	require.NoError(t, err)

	rng := rand.New(rand.NewSource(42))
	sampled, err := matrix.SampleFiltered(rng, Filter{
		PlatformPrefix: "qemu",
		Compiler:       "clang",
	})
	require.NoError(t, err)
	require.Contains(t, sampled.Platform, "qemu")
	require.Contains(t, sampled.Features, "clang")
	require.NotContains(t, sampled.Features, "gcc")
}
