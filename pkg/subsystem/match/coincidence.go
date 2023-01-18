// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package match

import "github.com/google/syzkaller/pkg/subsystem/entity"

// CoincidenceMatrix represents a matrix that, for every pair of subsystems
// A and B, stores the number of times A and B have coincided in the input data.
// So far we only need it for entity.Subsystem, so its interface is tailored to it.
type CoincidenceMatrix struct {
	matrix map[*entity.Subsystem]map[*entity.Subsystem]int
}

func MakeCoincidenceMatrix() *CoincidenceMatrix {
	return &CoincidenceMatrix{
		matrix: make(map[*entity.Subsystem]map[*entity.Subsystem]int),
	}
}

func (cm *CoincidenceMatrix) Record(items ...*entity.Subsystem) {
	for i := 0; i < len(items); i++ {
		for j := 0; j < len(items); j++ {
			cm.inc(items[i], items[j])
		}
	}
}

func (cm *CoincidenceMatrix) Count(a *entity.Subsystem) int {
	return cm.Get(a, a)
}

func (cm *CoincidenceMatrix) Get(a, b *entity.Subsystem) int {
	return cm.matrix[a][b]
}

func (cm *CoincidenceMatrix) NonEmptyPairs(cb func(a, b *entity.Subsystem, val int)) {
	for a, sub := range cm.matrix {
		for b, val := range sub {
			if a == b {
				continue
			}
			cb(a, b, val)
		}
	}
}

func (cm *CoincidenceMatrix) inc(a, b *entity.Subsystem) {
	subMatrix, ok := cm.matrix[a]
	if !ok {
		subMatrix = make(map[*entity.Subsystem]int)
		cm.matrix[a] = subMatrix
	}
	subMatrix[b]++
}
