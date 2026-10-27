// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package mgrconfig

import (
	"fmt"
	"testing"

	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseEnabledSyscalls(t *testing.T) {
	target, err := prog.GetTarget(targets.TestOS, targets.TestArch64)
	require.NoError(t, err)

	tests := []struct {
		name   string
		mode   DescriptionsMode
		enable []string
		// TODO: add disable tests as well.
		expectEnabled  []string
		expectDisabled []string
	}{
		{
			name:           "wildcard, no snapshot",
			mode:           ManualDescriptions,
			enable:         []string{"test"},
			expectDisabled: []string{"test$snapshot_only"},
		},
		{
			name:          "wildcard, snapshot",
			mode:          ManualDescriptions | SnapshotDescriptions,
			enable:        []string{"test"},
			expectEnabled: []string{"test$snapshot_only"},
		},
		{
			name:          "no wildcard, no snapshot",
			mode:          ManualDescriptions,
			enable:        []string{"test$snapshot_only"},
			expectEnabled: []string{"test$snapshot_only"},
		},
		{
			name:          "no wildcard, snapshot",
			mode:          ManualDescriptions | SnapshotDescriptions,
			enable:        []string{"test$snapshot_only"},
			expectEnabled: []string{"test$snapshot_only"},
		},
		{
			name:   "automatic allowed",
			mode:   ManualDescriptions | AutoDescriptions,
			enable: []string{"test"},
			expectEnabled: []string{
				"test$automatic",
				"test$automatic_helper",
				"test$manual",
			},
		},
		{
			name:   "manual only",
			mode:   ManualDescriptions,
			enable: []string{"test"},
			expectEnabled: []string{
				"test$automatic_helper",
				"test$manual",
			},
			expectDisabled: []string{
				"test$automatic",
			},
		},
		{
			name:   "auto only",
			mode:   AutoDescriptions,
			enable: []string{"test"},
			expectEnabled: []string{
				"test$automatic",
				"test$automatic_helper",
			},
			expectDisabled: []string{
				"test$manual",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ids, err := ParseEnabledSyscalls(target, test.enable,
				nil, test.mode)
			require.NoError(t, err)
			for _, enabled := range test.expectEnabled {
				assert.Contains(t, ids, target.SyscallMap[enabled].ID)
			}
			for _, disabled := range test.expectDisabled {
				assert.NotContains(t, ids, target.SyscallMap[disabled].ID)
			}
		})
	}
}

func TestCompleteDescriptionsMode(t *testing.T) {
	data := []byte(`{
		"target": "linux/amd64",
		"type": "none",
		"workdir": "/tmp",
		"syzkaller": "testdata/syzkaller",
		"experimental": {
			"descriptions_mode": "invalid"
		}
	}`)
	_, err := LoadData(data)
	require.Error(t, err)
	require.Contains(t, err.Error(), `invalid descriptions_mode "invalid", must be one of: any, auto, manual`)
}

func TestCompleteHTTPPublicURL(t *testing.T) {
	tests := []struct {
		name    string
		url     string
		want    string
		wantErr bool
	}{
		{name: "empty", url: "", want: ""},
		{name: "host", url: "http://example.com", want: "http://example.com"},
		{name: "host-port", url: "http://example.com:8080", want: "http://example.com:8080"},
		{name: "https-path", url: "https://example.com:8080/ui/", want: "https://example.com:8080/ui/"},
		{name: "escaped-path", url: `http://example.com/"><script>`, want: "http://example.com/%22%3E%3Cscript%3E"},
		{name: "no-scheme", url: "example.com:8080", wantErr: true},
		{name: "ftp", url: "ftp://example.com", wantErr: true},
		{name: "javascript", url: "javascript:alert(1)", wantErr: true},
		{name: "no-host", url: "http://", wantErr: true},
		{name: "bad-host", url: "http://bad host", wantErr: true},
		{name: "credentials", url: "http://user:pass@example.com", wantErr: true},
		{name: "query", url: "http://example.com/?token=secret", wantErr: true},
		{name: "fragment", url: "http://example.com/#frag", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data := []byte(fmt.Sprintf(`{
				"target": "linux/amd64",
				"type": "none",
				"workdir": "/tmp",
				"syzkaller": "testdata/syzkaller",
				"reproduce": false,
				"http": "localhost:1234",
				"http_public_url": %q
			}`, test.url))
			cfg, err := LoadData(data)
			if test.wantErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), "http_public_url")
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.want, cfg.HTTPPublicURL)
		})
	}
}

func TestFormatTarget(t *testing.T) {
	tests := []struct {
		os     string
		vmArch string
		arch   string
		want   string
	}{
		{targets.Linux, "amd64", "amd64", "linux/amd64"},
		{targets.Linux, "", "amd64", "linux/amd64"},
		{targets.Linux, "amd64", "386", "linux/amd64/386"},
		{targets.Linux, "arm64", "arm", "linux/arm64/arm"},
	}
	for _, tc := range tests {
		got := FormatTarget(tc.os, tc.vmArch, tc.arch)
		require.Equal(t, tc.want, got)
	}
}
