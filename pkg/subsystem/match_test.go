// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package subsystem

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPathMatcher(t *testing.T) {
	arm := &Subsystem{
		PathRules: []PathRule{
			{
				IncludeRegexp: `^arch/arm/.*$`,
				ExcludeRegexp: `^arch/arm/boot/dts/.*$`,
			},
			// Add a somewhat overlapping rule so that we test that no duplicates are returned.
			{
				IncludeRegexp: `^arch/arm/a/.*$`,
			},
			{IncludeRegexp: `^drivers/spi/spi-pl022\.c$`},
			{
				// nolint:lll
				IncludeRegexp: `^drivers/irqchip/irq-vic\.c$|^Documentation/devicetree/bindings/interrupt-controller/arm,vic\.yaml$`,
			},
		},
	}
	docs := &Subsystem{
		PathRules: []PathRule{
			{IncludeRegexp: `^Documentation/.*$`},
		},
	}
	m := MakePathMatcher([]*Subsystem{arm, docs})
	assert.ElementsMatch(t, []*Subsystem{arm, docs},
		m.Match(`Documentation/devicetree/bindings/interrupt-controller/arm,vic.yaml`))
	assert.ElementsMatch(t, []*Subsystem{arm}, m.Match(`arch/arm/a/a.c`))
	assert.ElementsMatch(t, []*Subsystem{docs}, m.Match(`Documentation/a/b/c.md`))
	assert.Empty(t, m.Match(`arch/boot/dts/a.c`))
}

func TestPathMatchOrder(t *testing.T) {
	s := &Subsystem{
		PathRules: []PathRule{
			{
				IncludeRegexp: `^a/b/.*$`,
				ExcludeRegexp: `^a/.*$`,
			},
		},
	}
	m := MakePathMatcher([]*Subsystem{s})
	// If we first exclude a/, then a/b/c never matches.
	assert.Empty(t, m.Match("a/b/c"))
}
