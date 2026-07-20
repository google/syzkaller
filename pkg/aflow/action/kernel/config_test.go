// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package kernel

import (
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestConfigGrep(t *testing.T) {
	t.Run("config inline text matching", func(t *testing.T) {
		state := configState{
			KernelConfig: "CONFIG_USB=y\nCONFIG_USB_NET=m\n# CONFIG_USB_SUPPORT is not set\nCONFIG_PCI=y\n",
		}

		res, err := grepConfigAction(nil, state, ConfigGrepArgs{Query: "config_usb"})
		require.NoError(t, err)
		require.Contains(t, res.Output, "CONFIG_USB=y")
		require.Contains(t, res.Output, "CONFIG_USB_NET=m")
		require.Contains(t, res.Output, "# CONFIG_USB_SUPPORT is not set")
		require.NotContains(t, res.Output, "CONFIG_PCI=y")
	})

	t.Run("config match truncation", func(t *testing.T) {
		var lines []string
		for i := range 120 {
			lines = append(lines, fmt.Sprintf("CONFIG_MATCH_%d=y", i))
		}
		state := configState{
			KernelConfig: strings.Join(lines, "\n"),
		}

		res, err := grepConfigAction(nil, state, ConfigGrepArgs{Query: "CONFIG_MATCH"})
		require.NoError(t, err)
		require.Contains(t, res.Output, "... (truncated remaining matches, please refine your query)")
	})

	t.Run("empty query returns BadCallError", func(t *testing.T) {
		_, err := grepConfigAction(nil, configState{KernelConfig: "CONFIG_USB=y\n"}, ConfigGrepArgs{})
		require.Error(t, err)
		require.Contains(t, err.Error(), "Query parameter must not be empty")
	})

	t.Run("kernel config not available", func(t *testing.T) {
		res, err := grepConfigAction(nil, configState{}, ConfigGrepArgs{Query: "CONFIG_USB"})
		require.NoError(t, err)
		require.Contains(t, res.Output, "Kernel config is not available.")
	})

	t.Run("no matching query", func(t *testing.T) {
		state := configState{
			KernelConfig: "CONFIG_USB=y\n",
		}
		res, err := grepConfigAction(nil, state, ConfigGrepArgs{Query: "CONFIG_NONEXISTENT"})
		require.NoError(t, err)
		require.Contains(t, res.Output, `No kernel config options found matching query "CONFIG_NONEXISTENT".`)
	})
}
