// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package qemu

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/google/syzkaller/pkg/config"
	"github.com/google/syzkaller/sys/targets"
	"github.com/google/syzkaller/vm/vmimpl"
	"github.com/stretchr/testify/require"
)

func TestBuildQemuArgsVsock(t *testing.T) {
	tests := []struct {
		name string
		cfg  string
		cid  uint32
		want []string
	}{
		{
			name: "disabled by default",
			cfg:  `{}`,
			want: nil,
		},
		{
			name: "enabled",
			cfg:  `{"vsock": true}`,
			cid:  1234567,
			want: []string{"vhost-vsock-pci,guest-cid=1234567"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			archCfg := archConfigs["linux/amd64"]
			cfg := &Config{
				Count:       1,
				CPU:         1,
				Mem:         1024,
				ImageDevice: "hda",
				Qemu:        archCfg.Qemu,
				QemuArgs:    archCfg.QemuArgs,
				NetDev:      archCfg.NetDev,
				Snapshot:    true,
			}
			require.NoError(t, config.LoadData(json.RawMessage(test.cfg), cfg))
			inst := &instance{
				cfg:        cfg,
				target:     targets.Get(targets.Linux, targets.AMD64),
				archConfig: archCfg,
				monport:    12345,
				vsockCID:   test.cid,
				SSHOptions: vmimpl.SSHOptions{Port: 23456},
			}
			args, err := inst.buildQemuArgs()
			require.NoError(t, err)
			require.Equal(t, test.want, vsockDevices(args))
		})
	}
}

func TestRandomVsockCID(t *testing.T) {
	seen := make(map[uint32]bool)
	for range 1000 {
		cid := randomVsockCID()
		require.GreaterOrEqual(t, cid, uint32(minVsockCID))
		require.LessOrEqual(t, cid, uint32(maxVsockCID))
		seen[cid] = true
	}
	// 1000 draws from ~2^31 values should essentially never collide.
	require.Greater(t, len(seen), 990)
}

// vsockDevices returns the values of all -device arguments that configure a vhost-vsock device.
func vsockDevices(args []string) []string {
	var res []string
	for i := 0; i+1 < len(args); i++ {
		if args[i] == "-device" && strings.HasPrefix(args[i+1], "vhost-vsock") {
			res = append(res, args[i+1])
		}
	}
	return res
}
