// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package linux

import "github.com/google/syzkaller/pkg/subsystem"

// parentTransformations applies all subsystem list transformations that have been implemented.
func parentTransformations(matrix *CoincidenceMatrix,
	list []*subsystem.Subsystem) ([]*subsystem.Subsystem, error) {
	list = dropSmallSubsystems(matrix, list)
	list = dropDuplicateSubsystems(matrix, list)
	err := setParents(matrix, list)
	if err != nil {
		return nil, err
	}
	return list, nil
}

// setParents attempts to determine the parent-child relations among the extracted subsystems.
// We assume A is a child of B if:
// 1) B covers more paths than A.
// 2) Most of the paths that relate to A also relate to B.
func setParents(matrix *CoincidenceMatrix, list []*subsystem.Subsystem) error {
	// Some subsystems might have already been dropeed.
	inInput := map[*subsystem.Subsystem]bool{}
	for _, item := range list {
		inInput[item] = true
	}
	matrix.NonEmptyPairs(func(a, b *subsystem.Subsystem, count int) {
		if !inInput[a] || !inInput[b] {
			return
		}
		// Demand that >= 50% paths are related.
		if 2*count/matrix.Count(a) >= 1 && matrix.Count(a) < matrix.Count(b) {
			a.Parents = append(a.Parents, b)
			a.ReachableParents() // make sure we haven't created a loop
		}
	})
	transitiveReduction(list)
	return nil
}

// dropSmallSubsystems removes subsystems for which we have found only a few matches in the filesystem tree.
func dropSmallSubsystems(matrix *CoincidenceMatrix, list []*subsystem.Subsystem) []*subsystem.Subsystem {
	const cutOffCount = 2

	newList := []*subsystem.Subsystem{}
	for _, item := range list {
		if matrix.Count(item) > cutOffCount || len(item.Syscalls) > 0 {
			newList = append(newList, item)
		}
	}
	return newList
}

// dropDuplicateSubsystems makes sure there are no duplicate subsystems.
// First, if subsystems A and B 100% overlap, we prefer the one that's alphabetically first.
// Second, if subsystem A is fully enclosed in subsystem B and constitutes more than 75% of B,
// we drop A, since it brings little value.
func dropDuplicateSubsystems(matrix *CoincidenceMatrix, list []*subsystem.Subsystem) []*subsystem.Subsystem {
	drop := map[*subsystem.Subsystem]struct{}{}
	firstIsBetter := func(first, second *subsystem.Subsystem) bool {
		firstEmail, secondEmail := "", ""
		if len(first.Lists) > 0 {
			firstEmail = first.Lists[0]
		}
		if len(second.Lists) > 0 {
			secondEmail = second.Lists[0]
		}
		return firstEmail < secondEmail
	}
	matrix.NonEmptyPairs(func(a, b *subsystem.Subsystem, count int) {
		// Only consider cases when A is fully enclosed in B, i.e. M[A][B] == M[A][A].
		if count != matrix.Count(a) {
			return
		}
		// If A and B 100% coincide, eliminate A and keep B if A > B.
		if count == matrix.Count(b) {
			if firstIsBetter(a, b) {
				return
			}
			drop[a] = struct{}{}
			return
		}
		// If A constitutes > 75% of B, drop A.
		if 4*matrix.Count(a)/matrix.Count(b) >= 3 {
			drop[a] = struct{}{}
		}
	})
	newList := []*subsystem.Subsystem{}
	for _, item := range list {
		if _, exists := drop[item]; !exists {
			newList = append(newList, item)
		}
	}
	return newList
}

// The algorithm runs in O(E * (E + V)).
// We expect that E is quite low here, so it should be fine.
func transitiveReduction(list []*subsystem.Subsystem) {
	for _, s := range list {
		removeParents := map[*subsystem.Subsystem]bool{}
		for _, p := range s.Parents {
			for otherP := range p.ReachableParents() {
				removeParents[otherP] = true
			}
		}
		newParents := []*subsystem.Subsystem{}
		for _, p := range s.Parents {
			if !removeParents[p] {
				newParents = append(newParents, p)
			}
		}
		s.Parents = newParents
	}
}
