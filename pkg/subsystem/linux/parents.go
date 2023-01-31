// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package linux

import (
	"fmt"

	"github.com/google/syzkaller/pkg/subsystem/entity"
	"github.com/google/syzkaller/pkg/subsystem/match"
)

// SetParents attempts to determine the parent-child relations among the extracted subsystems.
// We assume A is a child of B if:
// 1) B covers more paths than A.
// 2) Most of the paths that relate to A also relate to B.
func SetParents(matrix *match.CoincidenceMatrix, list []*entity.Subsystem) error {
	matrix.NonEmptyPairs(func(a, b *entity.Subsystem, count int) {
		// Demand that > 2/3 paths are related.
		if 3*count/matrix.Count(a) >= 2 && matrix.Count(a) < matrix.Count(b) {
			a.Parents = append(a.Parents, b)
		}
	})
	// Just in case.
	if loopsExist(list) {
		return fmt.Errorf("there are loops in the parents relation")
	}
	transitiveReduction(list)
	return nil
}

// The algorithm runs in O(E * (E + V)).
// We expect that E is quite low here, so it should be fine.
func transitiveReduction(list []*entity.Subsystem) {
	for _, s := range list {
		removeParents := map[*entity.Subsystem]bool{}
		for _, p := range s.Parents {
			for otherP := range p.ReachableParents() {
				removeParents[otherP] = true
			}
		}
		newParents := []*entity.Subsystem{}
		for _, p := range s.Parents {
			if !removeParents[p] {
				newParents = append(newParents, p)
			}
		}
		s.Parents = newParents
	}
}

// loopsExist is a helper method that verifies that the resulting graph has no loops.
func loopsExist(list []*entity.Subsystem) bool {
	type graphNode struct {
		obj     *entity.Subsystem
		entered bool
		left    bool
	}
	nodes := []*graphNode{}
	objToNode := map[*entity.Subsystem]*graphNode{}
	for _, obj := range list {
		node := &graphNode{obj: obj}
		nodes = append(nodes, node)
		objToNode[obj] = node
	}
	var dfs func(*graphNode) bool
	dfs = func(node *graphNode) bool {
		if node.left {
			return false
		}
		if node.entered {
			// We've found a cycle.
			return true
		}
		node.entered = true
		anyLoop := false
		for _, parent := range node.obj.Parents {
			anyLoop = anyLoop || dfs(objToNode[parent])
		}
		node.left = true
		return anyLoop
	}
	for _, node := range nodes {
		if dfs(node) {
			return true
		}
	}
	return false
}
