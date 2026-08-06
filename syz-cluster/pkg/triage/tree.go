// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package triage

import (
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"

	"github.com/google/syzkaller/syz-cluster/pkg/api"
)

func GetStableRCVersion(series *api.Series) string {
	if series == nil || series.XStable != "review" {
		return ""
	}
	hasStableCc := slices.ContainsFunc(series.Cc, func(cc string) bool {
		return strings.EqualFold(cc, stableEmail)
	})
	if !hasStableCc {
		return ""
	}
	return stableVersion(series.XKernelTestBranch)
}

func IsStableRC(series *api.Series) bool {
	return GetStableRCVersion(series) != ""
}

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

func FindTreeByName(trees []*api.Tree, name string) *api.Tree {
	idx := slices.IndexFunc(trees, func(t *api.Tree) bool {
		return t.Name == name
	})
	if idx != -1 {
		return trees[idx]
	}
	return nil
}

func IsStableTree(tree *api.Tree) bool {
	if tree == nil {
		return false
	}
	return tree.Type == api.TreeTypeStable
}

func CandidateTrees(trees []*api.Tree, series *api.Series) ([]*api.Tree, error) {
	if version := GetStableRCVersion(series); version != "" {
		if tree := FindTreeByName(trees, "stable-"+version); tree != nil {
			return []*api.Tree{tree}, nil
		}
		return nil, fmt.Errorf("stable tree %v not found in global-config.yaml", version)
	}
	if hasStableVersionTag(series) {
		return nil, fmt.Errorf("developer stable backport skipped")
	}
	return slices.DeleteFunc(slices.Clone(trees), IsStableTree), nil
}

func hasStableVersionTag(series *api.Series) bool {
	return slices.ContainsFunc(series.SubjectTags, func(s string) bool {
		return stableVersion(s) != ""
	})
}

var stableVersionRe = regexp.MustCompile(`^(?:linux-|stable-)?v?(\d+\.\d+)(?:\.y|\.\d+)?$`)

func stableVersion(s string) string {
	m := stableVersionRe.FindStringSubmatch(s)
	if m == nil {
		return ""
	}
	return m[1]
}

const stableEmail = "stable@vger.kernel.org"
