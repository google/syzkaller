// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package subsystem

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReachableParents(t *testing.T) {
	parentParent := &Subsystem{}
	parentA := &Subsystem{Parents: []*Subsystem{parentParent}}
	parentB := &Subsystem{Parents: []*Subsystem{parentParent}}
	entity := &Subsystem{Parents: []*Subsystem{parentA, parentB}}

	retParents := []*Subsystem{}
	for item := range entity.ReachableParents() {
		retParents = append(retParents, item)
	}
	assert.ElementsMatch(t, retParents, []*Subsystem{parentA, parentB, parentParent})
}
