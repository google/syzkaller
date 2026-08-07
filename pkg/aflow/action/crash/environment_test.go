// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package crash

import (
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestGetEnvironment(t *testing.T) {
	baseState := EnvironmentState{
		TargetOS:   "linux",
		TargetArch: "amd64",
		Type:       "qemu",
		VM: json.RawMessage(`{
			"cmdline": "root=/dev/sda1 dummy_hcd.num=1",
			"qemu_args": "-enable-kvm -m 4096M"
		}`),
	}

	t.Run("valid metadata without config", func(t *testing.T) {
		res, err := getEnvironmentAction(nil, baseState, EnvironmentArgs{Query: "CONFIG_USB"})
		require.NoError(t, err)
		require.Contains(t, res.Output, "Target OS: linux")
		require.Contains(t, res.Output, "Target Arch: amd64")
		require.Contains(t, res.Output, "VM Type: qemu")
		require.Contains(t, res.Output, "VM Cmdline: root=/dev/sda1 dummy_hcd.num=1")
		require.Contains(t, res.Output, "VM Qemu Args: -enable-kvm -m 4096M")
		require.Contains(t, res.Output, "Kernel config is not available.")
	})

	t.Run("kconfig inline text matching", func(t *testing.T) {
		state := baseState
		state.KernelConfig = "CONFIG_USB=y\nCONFIG_USB_NET=m\n# CONFIG_USB_SUPPORT is not set\nCONFIG_PCI=y\n"

		res, err := getEnvironmentAction(nil, state, EnvironmentArgs{Query: "config_usb"})
		require.NoError(t, err)
		require.Contains(t, res.Output, "CONFIG_USB=y")
		require.Contains(t, res.Output, "CONFIG_USB_NET=m")
		require.Contains(t, res.Output, "# CONFIG_USB_SUPPORT is not set")
		require.NotContains(t, res.Output, "CONFIG_PCI=y")
	})

	t.Run("kconfig match truncation", func(t *testing.T) {
		var lines []string
		for i := range 120 {
			lines = append(lines, fmt.Sprintf("CONFIG_MATCH_%d=y", i))
		}
		state := baseState
		state.KernelConfig = strings.Join(lines, "\n")

		res, err := getEnvironmentAction(nil, state, EnvironmentArgs{Query: "CONFIG_MATCH"})
		require.NoError(t, err)
		require.Contains(t, res.Output, "... (truncated remaining matches, please refine your query)")
	})

	t.Run("empty query returns BadCallError", func(t *testing.T) {
		_, err := getEnvironmentAction(nil, baseState, EnvironmentArgs{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "Query parameter must not be empty")
	})
}
