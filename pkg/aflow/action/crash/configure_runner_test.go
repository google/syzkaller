// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package crash

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFormatEnvironment(t *testing.T) {
	args := ConfigureRunnerArgs{
		TargetOS:   "linux",
		TargetArch: "amd64",
		Type:       "qemu",
		VM: json.RawMessage(`{
			"cmdline": "root=/dev/sda1 dummy_hcd.num=1",
			"qemu_args": "-enable-kvm -m 4096M"
		}`),
	}

	got := formatEnvironment(args)
	want := `Target OS: linux
Target Arch: amd64
VM Type: qemu
VM Cmdline: root=/dev/sda1 dummy_hcd.num=1
VM Qemu Args: -enable-kvm -m 4096M
`
	require.Equal(t, want, got)
}
