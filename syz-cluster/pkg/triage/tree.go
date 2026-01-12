// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package triage

import (
	"sort"
	"strings"

	"github.com/google/syzkaller/syz-cluster/pkg/api"
)

// SelectTrees returns an ordered list of git trees to apply the series to.
func SelectTrees(series *api.Series, trees []*api.Tree) []*api.Tree {
	seriesCc := map[string]bool{}
	for _, cc := range series.Cc {
		seriesCc[strings.ToLower(cc)] = true
	}
	tagsMap := map[string]bool{}
	for _, tag := range series.SubjectTags {
		tagsMap[tag] = true
	}
	var result []*api.Tree
	for _, tree := range trees {
		if tagsMap[tree.Name] {
			// If the tree was directly mentioned in the patch subject, always take it.
			result = append(result, tree)
			continue
		}
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
		result = append(result, tree)
	}
	sort.SliceStable(result, func(i, j int) bool {
		// First the trees from the patch subject, then everything else.
		return tagsMap[result[i].Name] && !tagsMap[result[j].Name]
	})
	return result
}

func FindTree(trees []*api.Tree, branch string) (int, string) {
	for idx, tree := range trees {
		branchName, ok := strings.CutPrefix(branch, tree.Name+"/")
		if ok {
			return idx, branchName
		}
	}
	return -1, ""
}
