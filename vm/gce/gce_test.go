// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package gce

import (
	"testing"

	"github.com/google/syzkaller/sys/targets"
	"github.com/google/syzkaller/vm/vmimpl"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseConfig(t *testing.T) {
	tests := []struct {
		name    string
		env     vmimpl.Env
		wantErr string
	}{
		{
			name: "minimal",
			env: vmimpl.Env{
				Name:   "syz-manager",
				Arch:   targets.AMD64,
				Image:  "image",
				Config: []byte(`{"machine_type": "e2-standard-2", "gcs_path": "bucket/path"}`),
			},
		},
		{
			name: "count out of range",
			env: vmimpl.Env{
				Name:   "syz-manager",
				Image:  "image",
				Config: []byte(`{"count": 0, "machine_type": "e2-standard-2", "gcs_path": "bucket/path"}`),
			},
			wantErr: "invalid config param count",
		},
		{
			name: "missing machine_type",
			env: vmimpl.Env{
				Name:   "syz-manager",
				Image:  "image",
				Config: []byte(`{"gcs_path": "bucket/path"}`),
			},
			wantErr: "machine_type parameter is empty",
		},
		{
			name: "both image and gce_image",
			env: vmimpl.Env{
				Name:   "syz-manager",
				Image:  "image",
				Config: []byte(`{"machine_type": "e2-standard-2", "gce_image": "image"}`),
			},
			wantErr: "both image and gce_image are specified",
		},
		{
			name: "auto_delete_image with gce_image",
			env: vmimpl.Env{
				Name:   "syz-manager",
				Config: []byte(`{"machine_type": "e2-standard-2", "gce_image": "image", "auto_delete_image": true}`),
			},
			wantErr: "auto_delete_image requires gce_image to be empty",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg, err := parseConfig(&test.env)
			if test.wantErr != "" {
				assert.ErrorContains(t, err, test.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, 1, cfg.Count)
			assert.Equal(t, "e2-standard-2", cfg.MachineType)
			assert.True(t, cfg.Preemptible)
			assert.True(t, cfg.DisplayDevice)
			assert.False(t, cfg.AutoDeleteImage)
		})
	}
}

func TestPoolClose(t *testing.T) {
	// Close() must work both without the label refresh goroutine and must stop it if it was started
	// (the goroutine only talks to GCE on ticks, which don't happen within the test).
	pool := &Pool{closed: make(chan struct{})}
	assert.NoError(t, pool.Close())

	pool = &Pool{closed: make(chan struct{})}
	pool.wg.Go(pool.refreshImageLabelLoop)
	assert.NoError(t, pool.Close())
}
