// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package gce

import (
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/gce"
	"github.com/google/syzkaller/sys/targets"
	"github.com/google/syzkaller/vm/vmimpl"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/api/compute/v1"
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

func TestCanReuseImage(t *testing.T) {
	const imageHash = "22596363b3de40b06f981fb85d82312e8c0ed511"
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	image := func(status string, labels map[string]string) *compute.Image {
		return &compute.Image{
			Status: status,
			Labels: labels,
		}
	}
	tests := []struct {
		name  string
		image *compute.Image
		want  bool
	}{
		{
			name:  "no image",
			image: nil,
		},
		{
			// Images created by older syzkaller versions don't have the hash label.
			name:  "no labels",
			image: image("READY", nil),
		},
		{
			name: "different hash",
			image: image("READY", map[string]string{
				gce.LabelImageHash: "other",
			}),
		},
		{
			name: "not ready",
			image: image("PENDING", map[string]string{
				gce.LabelImageHash: imageHash,
			}),
		},
		{
			// Non-auto-deleted images are never deleted, their age does not matter.
			name: "persistent",
			image: image("READY", map[string]string{
				gce.LabelImageHash:  imageHash,
				gce.LabelLastActive: gce.LastActiveLabelValue(now.Add(-30 * 24 * time.Hour)),
			}),
			want: true,
		},
		{
			name: "auto-deleted fresh",
			image: image("READY", map[string]string{
				gce.LabelImageHash:  imageHash,
				gce.LabelAutoDelete: "true",
				gce.LabelLastActive: gce.LastActiveLabelValue(now.Add(-maxReuseAge / 2)),
			}),
			want: true,
		},
		{
			// The cleanup job may delete it before we refresh the label.
			name: "auto-deleted stale",
			image: image("READY", map[string]string{
				gce.LabelImageHash:  imageHash,
				gce.LabelAutoDelete: "true",
				gce.LabelLastActive: gce.LastActiveLabelValue(now.Add(-maxReuseAge)),
			}),
		},
		{
			name: "auto-deleted without last active",
			image: image("READY", map[string]string{
				gce.LabelImageHash:  imageHash,
				gce.LabelAutoDelete: "true",
			}),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.want, canReuseImage(test.image, imageHash, now))
		})
	}
}
