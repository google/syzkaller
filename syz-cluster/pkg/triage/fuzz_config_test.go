// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package triage

import (
	"testing"

	"github.com/google/syzkaller/syz-cluster/pkg/api"
	"github.com/stretchr/testify/assert"
)

func TestSelectFuzzConfig(t *testing.T) {
	configs := []*api.TriageFuzzConfig{
		{
			EmailLists: []string{"bpf@list"},
			FuzzConfig: api.FuzzConfig{Config: "bpf"},
		},
		{
			EmailLists: []string{"net@list"},
			FuzzConfig: api.FuzzConfig{Config: "net"},
		},
		{
			EmailLists: nil,
			FuzzConfig: api.FuzzConfig{Config: "mainline"},
		},
	}
	tests := []struct {
		testName string
		result   string
		series   *api.Series
	}{
		{
			testName: "select-first",
			result:   "bpf",
			series:   &api.Series{Cc: []string{"bpf@list", "net@list"}},
		},
		{
			testName: "fallback",
			result:   "mainline",
			series:   &api.Series{Cc: []string{"unknown@list"}},
		},
	}

	for _, test := range tests {
		t.Run(test.testName, func(t *testing.T) {
			ret := SelectFuzzConfig(test.series, configs)
			assert.Equal(t, test.result, ret.Config)
		})
	}
}
