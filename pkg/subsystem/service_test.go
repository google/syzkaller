// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package subsystem

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestServiceChildren(t *testing.T) {
	unrelated := &Subsystem{Name: "unrelated"}
	parent := &Subsystem{Name: "parent"}
	childA := &Subsystem{Name: "childA", Parents: []*Subsystem{parent}}
	childB := &Subsystem{Name: "childB", Parents: []*Subsystem{parent}}
	service := MustMakeService([]*Subsystem{unrelated, parent, childA, childB})
	assert.ElementsMatch(t, service.Children(parent), []*Subsystem{childA, childB})
}
