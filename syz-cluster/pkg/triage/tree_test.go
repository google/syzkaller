// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package triage

import (
	"testing"

	"github.com/google/syzkaller/syz-cluster/pkg/api"
	"github.com/stretchr/testify/assert"
)

func TestSelectTree(t *testing.T) {
	trees := []*api.Tree{
		{
			Name:       "mainline",
			EmailLists: nil,
			Priority:   0,
		},
		{
			Name:       "net",
			EmailLists: []string{"net@list"},
			Priority:   1,
		},
		{
			Name:       "wireless",
			EmailLists: []string{"wireless@list"},
			Priority:   2,
		},
	}
	tests := []struct {
		testName string
		result   string
		series   *api.Series
	}{
		{
			testName: "only-net",
			result:   "net",
			series:   &api.Series{Cc: []string{"net@list"}},
		},
		{
			testName: "prefer-wireless",
			result:   "wireless",
			series:   &api.Series{Cc: []string{"net@list", "wireless@list"}},
		},
		{
			testName: "fallback",
			result:   "mainline",
			series:   &api.Series{Cc: []string{"unknown@list"}},
		},
	}

	for _, test := range tests {
		test := test
		t.Run(test.testName, func(t *testing.T) {
			ret := SelectTree(test.series, trees)
			assert.NotNil(t, ret)
			assert.Equal(t, test.result, ret.Name)
		})
	}
}
