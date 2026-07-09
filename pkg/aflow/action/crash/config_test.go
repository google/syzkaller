// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package crash

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTargetConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		config  TargetConfig
		wantErr bool
	}{
		{
			name: "valid qemu config",
			config: TargetConfig{
				TargetArch: "amd64",
				Type:       "qemu",
			},
			wantErr: false,
		},
		{
			name: "valid gce config",
			config: TargetConfig{
				TargetArch: "amd64",
				Type:       "gce",
			},
			wantErr: false,
		},
		{
			name: "unsupported target arch",
			config: TargetConfig{
				TargetArch: "invalid",
				Type:       "qemu",
			},
			wantErr: true,
		},
		{
			name: "unsupported VM type",
			config: TargetConfig{
				TargetArch: "amd64",
				Type:       "invalid",
			},
			wantErr: true,
		},
		{
			name: "valid custom sandbox",
			config: TargetConfig{
				TargetArch: "amd64",
				Type:       "qemu",
				Sandbox:    "namespace",
			},
			wantErr: false,
		},
		{
			name: "unsupported sandbox type",
			config: TargetConfig{
				TargetArch: "amd64",
				Type:       "qemu",
				Sandbox:    "invalid",
			},
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.config.Validate()
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func setupDummySyzkaller(t *testing.T) string {
	dir := t.TempDir()
	binDir := filepath.Join(dir, "bin", "linux_amd64")
	err := os.MkdirAll(binDir, 0755)
	require.NoError(t, err)

	for _, file := range []string{"syz-execprog", "syz-executor"} {
		err = os.WriteFile(filepath.Join(binDir, file), []byte("dummy"), 0644)
		require.NoError(t, err)
	}
	return dir
}

func TestBuildConfig(t *testing.T) {
	syzDir := setupDummySyzkaller(t)

	createDummyImage := func(t *testing.T) string {
		tmp := t.TempDir()
		img := filepath.Join(tmp, "dummy_image")
		err := os.WriteFile(img, []byte("dummy image data"), 0644)
		require.NoError(t, err)
		return img
	}

	t.Run("qemu defaults", func(t *testing.T) {
		img := createDummyImage(t)
		cfg := TargetConfig{
			TargetArch: "amd64",
			Type:       "qemu",
			Syzkaller:  syzDir,
			Image:      img,
			KernelObj:  "dummy_kernel_obj",
		}
		res, err := BuildConfig(cfg, t.TempDir())
		require.NoError(t, err)
		require.Equal(t, "qemu", res.Type)
		require.Equal(t, "none", res.Sandbox)
		require.Equal(t, img, res.Image)
		require.Equal(t, "any", res.Experimental.DescriptionsMode)

		var vmCfg map[string]any
		err = json.Unmarshal(res.VM, &vmCfg)
		require.NoError(t, err)
		expectedKernel := filepath.Join("dummy_kernel_obj", filepath.FromSlash("arch/x86/boot/bzImage"))
		require.Equal(t, expectedKernel, vmCfg["kernel"])
	})

	t.Run("qemu custom options", func(t *testing.T) {
		img := createDummyImage(t)
		vmRaw := json.RawMessage(`{"count":2,"cpu":"4"}`)
		straceBin := filepath.Join(t.TempDir(), "strace")
		err := os.WriteFile(straceBin, []byte("dummy strace"), 0755)
		require.NoError(t, err)

		cfg := TargetConfig{
			TargetArch: "amd64",
			Type:       "qemu",
			Syzkaller:  syzDir,
			Image:      img,
			KernelObj:  "dummy_kernel_obj",
			VM:         vmRaw,
			Sandbox:    "namespace",
			NeedStrace: true,
			StraceBin:  straceBin,
		}
		res, err := BuildConfig(cfg, t.TempDir())
		require.NoError(t, err)
		require.Equal(t, "namespace", res.Sandbox)
		require.Equal(t, straceBin, res.StraceBin)
		require.False(t, res.StraceBinOnTarget)

		var vmCfg map[string]any
		err = json.Unmarshal(res.VM, &vmCfg)
		require.NoError(t, err)
		require.Equal(t, float64(2), vmCfg["count"])
		require.Equal(t, "4", vmCfg["cpu"])
		expectedKernel := filepath.Join("dummy_kernel_obj", filepath.FromSlash("arch/x86/boot/bzImage"))
		require.Equal(t, expectedKernel, vmCfg["kernel"])
	})

	t.Run("gce image embed error", func(t *testing.T) {
		img := createDummyImage(t)
		cfg := TargetConfig{
			TargetArch: "amd64",
			Type:       "gce",
			Syzkaller:  syzDir,
			Image:      img,
			KernelObj:  "dummy_kernel_obj",
		}
		_, err := BuildConfig(cfg, t.TempDir())
		require.Error(t, err)
		require.Contains(t, err.Error(), "failed to embed kernel")
	})
}
