// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package triage

import (
	"testing"

	"github.com/google/syzkaller/syz-cluster/pkg/api"
	"github.com/stretchr/testify/assert"
)

func TestSelectFuzzConfig(t *testing.T) {
	bpf := &api.FuzzTriageTarget{EmailLists: []string{"bpf@list"}}
	net := &api.FuzzTriageTarget{EmailLists: []string{"net@list"}}
	mainline := &api.FuzzTriageTarget{EmailLists: nil}
	configs := []*api.FuzzTriageTarget{bpf, net, mainline}
	tests := []struct {
		testName string
		result   *api.FuzzTriageTarget
		series   *api.Series
	}{
		{
			testName: "select-first",
			result:   bpf,
			series:   &api.Series{Cc: []string{"bpf@list", "net@list"}},
		},
		{
			testName: "fallback",
			result:   mainline,
			series:   &api.Series{Cc: []string{"unknown@list"}},
		},
	}

	for _, test := range tests {
		t.Run(test.testName, func(t *testing.T) {
			ret := SelectFuzzConfig(test.series, configs)
			assert.Equal(t, test.result, ret)
		})
	}
}
