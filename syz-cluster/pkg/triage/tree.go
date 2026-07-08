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

var stableVersionRe = regexp.MustCompile(`^(?:stable-)?v?(\d+\.\d+)(?:\.y|\.\d+)?$`)

func StableVersion(s string) string {
	m := stableVersionRe.FindStringSubmatch(s)
	if m == nil {
		return ""
	}
	return m[1]
}

var stableRCRe = regexp.MustCompile(`\b\d+\.\d+\.\d+-rc\d+\s+review\b`)

func GetStableRCVersions(series *api.Series) []string {
	hasStableCc := slices.ContainsFunc(series.Cc, func(cc string) bool {
		return strings.ToLower(cc) == "stable@vger.kernel.org"
	})
	hasStableTitle := stableRCRe.MatchString(series.Title)
	if !hasStableCc || !hasStableTitle {
		return nil
	}
	var versions []string
	for _, tag := range series.SubjectTags {
		if v := StableVersion(tag); v != "" && !slices.Contains(versions, v) {
			versions = append(versions, v)
		}
	}
	return versions
}

func HasStableVersionTag(series *api.Series) bool {
	return slices.ContainsFunc(series.SubjectTags,
		func(s string) bool {
			return StableVersion(s) != ""
		},
	)
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
	return tree.Type == "stable"
}

func CandidateTrees(trees []*api.Tree, series *api.Series) ([]*api.Tree, error) {
	stableTrees, nonStableTrees := PartitionTrees(trees)
	if stableVersions := GetStableRCVersions(series); len(stableVersions) > 0 {
		minimizedStableTrees := slices.DeleteFunc(stableTrees, func(tree *api.Tree) bool {
			return !slices.Contains(stableVersions, StableVersion(tree.Name))
		})
		if len(minimizedStableTrees) == 0 {
			return nil, fmt.Errorf("no suitable base kernel trees found")
		}
		return minimizedStableTrees, nil
	} else if HasStableVersionTag(series) {
		return nil, fmt.Errorf("developer stable backport skipped")
	}
	return nonStableTrees, nil
}

// PartitionTrees splits trees into stable and non-stable tree slices.
func PartitionTrees(trees []*api.Tree) (stableTrees, nonStableTrees []*api.Tree) {
	for i := range trees {
		if IsStableTree(trees[i]) {
			stableTrees = append(stableTrees, trees[i])
		} else {
			nonStableTrees = append(nonStableTrees, trees[i])
		}
	}
	return
}
