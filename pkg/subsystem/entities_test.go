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

func TestSubsystemEmails(t *testing.T) {
	parentParent := &Subsystem{Lists: []string{"a@list.com"}, Maintainers: []string{"a@person.com"}}
	parent1 := &Subsystem{Lists: []string{"b@list.com"}, Maintainers: []string{"b@person.com"}}
	parent2 := &Subsystem{
		Lists:       []string{"c@list.com"},
		Maintainers: []string{"c@person.com"},
		Parents:     []*Subsystem{parentParent},
	}
	subsystem := &Subsystem{
		Lists:       []string{"d@list.com"},
		Maintainers: []string{"d@person.com"},
		Parents:     []*Subsystem{parent1, parent2},
	}
	assert.ElementsMatch(t, subsystem.Emails(), []string{
		"a@list.com", "b@list.com", "c@list.com", "d@list.com", "d@person.com",
	})
}

func TestFilterList(t *testing.T) {
	parentParent := &Subsystem{}
	parentA := &Subsystem{Parents: []*Subsystem{parentParent}}
	parentB := &Subsystem{Parents: []*Subsystem{parentParent}}
	entity := &Subsystem{Parents: []*Subsystem{parentA, parentB}}

	newList := FilterList([]*Subsystem{parentA, parentB, parentParent, entity},
		func(s *Subsystem) bool {
			return s != parentB
		},
	)
	assert.Len(t, newList, 3)
	assert.ElementsMatch(t, entity.Parents, []*Subsystem{parentA})
}
