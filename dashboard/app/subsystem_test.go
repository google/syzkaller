// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSubsytemMaintainers(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	// This also indirectly tests getSubsystemService.
	assert.ElementsMatch(t,
		subsystemMaintainers(c.ctx, "test1", "subsystemA"),
		[]string{
			"subsystemA@list.com", "subsystemA@person.com",
		},
	)
	assert.ElementsMatch(t, subsystemMaintainers(c.ctx, "test1", "does-not-exist"), []string{})
}
