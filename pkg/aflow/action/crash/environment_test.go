// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package crash

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetEnvironment(t *testing.T) {
	state := EnvironmentState{
		TargetOS:   "linux",
		TargetArch: "amd64",
		Type:       "qemu",
		VM: json.RawMessage(`{
			"cmdline": "root=/dev/sda1 dummy_hcd.num=1",
			"qemu_args": "-enable-kvm -m 4096M"
		}`),
	}

	res, err := getEnvironmentAction(nil, state, EnvironmentArgs{})
	require.NoError(t, err)
	require.Contains(t, res.Output, "Target OS: linux")
	require.Contains(t, res.Output, "Target Arch: amd64")
	require.Contains(t, res.Output, "VM Type: qemu")
	require.Contains(t, res.Output, "VM Cmdline: root=/dev/sda1 dummy_hcd.num=1")
	require.Contains(t, res.Output, "VM Qemu Args: -enable-kvm -m 4096M")
}
