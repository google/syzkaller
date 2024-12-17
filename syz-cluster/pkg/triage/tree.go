// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package triage

import (
	"strings"

	"github.com/google/syzkaller/syz-cluster/pkg/api"
)

// TODO: add tests.
func SelectTree(series *api.Series, trees []*api.Tree) *api.Tree {
	seriesCc := map[string]bool{}
	for _, cc := range series.Cc {
		seriesCc[strings.ToLower(cc)] = true
	}
	var best *api.Tree
	for _, tree := range trees {
		intersects := false
		for _, cc := range tree.EmailLists {
			if seriesCc[strings.ToLower(cc)] {
				intersects = true
				break
			}
		}
		if len(tree.EmailLists) > 0 && !intersects {
			continue
		}
		if best == nil || tree.Priority > best.Priority {
			best = tree
		}
	}
	return best
}
