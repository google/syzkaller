// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"math/rand"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLoadMatrix(t *testing.T) {
	matrix, err := LoadMatrix("matrix.yaml")
	require.NoError(t, err)
	require.NotEmpty(t, matrix.Base.Features)
	require.Contains(t, matrix.Axes, "platform")
	require.Contains(t, matrix.Axes, "sanitizer")
	require.Contains(t, matrix.Axes, "preemption")
	require.Contains(t, matrix.Overlays, "lockdep")
	require.Contains(t, matrix.Overlays, "storage_filesystems")
}

func TestSampleDeterminism(t *testing.T) {
	matrix, err := LoadMatrix("matrix.yaml")
	require.NoError(t, err)

	rng1 := rand.New(rand.NewSource(42))
	s1, err := matrix.Sample(rng1)
	require.NoError(t, err)

	rng2 := rand.New(rand.NewSource(42))
	s2, err := matrix.Sample(rng2)
	require.NoError(t, err)

	require.Equal(t, s1.Tag, s2.Tag)
	require.Equal(t, s1.Platform, s2.Platform)
	require.Equal(t, s1.Cmdline, s2.Cmdline)
	require.Equal(t, s1.QemuArgs, s2.QemuArgs)
	require.Equal(t, s1.Features, s2.Features)
	require.Equal(t, s1.SelectedAxes, s2.SelectedAxes)
	require.Equal(t, s1.SelectedOverlays, s2.SelectedOverlays)
}

func TestPlatformFiltering(t *testing.T) {
	matrix := &Matrix{
		Axes: map[string][]AxisOption{
			"platform": {
				{Name: "gce_arm64", Weight: 1.0, Features: []string{"arm64", "gce"}},
			},
		},
		Overlays: map[string]OverlayOption{
			"qemu_only_overlay": {
				Prob:        1.0,
				Platforms:   []string{"qemu_x86_64"},
				Features:    []string{"qemu_feat"},
				QemuArgs:    "-device custom",
				Description: "QEMU only",
			},
			"universal_overlay": {
				Prob:        1.0,
				Features:    []string{"universal_feat"},
				Description: "Universal",
			},
		},
	}

	rng := rand.New(rand.NewSource(1))
	sampled, err := matrix.Sample(rng)
	require.NoError(t, err)
	require.Equal(t, "gce_arm64", sampled.Platform)
	require.NotContains(t, sampled.SelectedOverlays, "qemu_only_overlay")
	require.Contains(t, sampled.SelectedOverlays, "universal_overlay")
	require.NotContains(t, sampled.Features, "qemu_feat")
	require.Contains(t, sampled.Features, "universal_feat")
}

func TestFormatKconfInstancesYAML(t *testing.T) {
	manifest := []*SampledConfig{
		{
			Tag:      "inst-1",
			Features: []string{"kasan", "x86_64", "upstream"},
		},
		{
			Tag:      "inst-2",
			Features: []string{"kmsan", "arm64", "gce"},
		},
	}

	yamlOut, err := FormatKconfInstancesYAML(manifest)
	require.NoError(t, err)
	require.Contains(t, yamlOut, "inst-1:")
	require.Contains(t, yamlOut, "- kasan")
	require.Contains(t, yamlOut, "inst-2:")
	require.Contains(t, yamlOut, "- kmsan")
}
