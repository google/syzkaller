// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package match

import (
	"testing"

	"github.com/google/syzkaller/pkg/subsystem/entity"
	"github.com/stretchr/testify/assert"
)

func TestPathMatcher(t *testing.T) {
	arm := &entity.Subsystem{
		PathRules: []entity.PathRule{
			{
				IncludeRegexp: `^arch/arm/.*$`,
				ExcludeRegexp: `^arch/arm/boot/dts/.*$`,
			},
			{IncludeRegexp: `^drivers/spi/spi-pl022\.c$`},
			{
				// nolint:lll
				IncludeRegexp: `^drivers/irqchip/irq-vic\.c$|^Documentation/devicetree/bindings/interrupt-controller/arm,vic\.yaml$`,
			},
		},
	}
	docs := &entity.Subsystem{
		PathRules: []entity.PathRule{
			{IncludeRegexp: `^Documentation/.*$`},
		},
	}
	m := MakePathMatcher([]*entity.Subsystem{arm, docs})
	assert.ElementsMatch(t, []*entity.Subsystem{arm, docs},
		m.Match(`Documentation/devicetree/bindings/interrupt-controller/arm,vic.yaml`))
	assert.ElementsMatch(t, []*entity.Subsystem{arm}, m.Match(`arch/arm/a.c`))
	assert.ElementsMatch(t, []*entity.Subsystem{docs}, m.Match(`Documentation/a/b/c.md`))
	assert.Empty(t, m.Match(`arch/boot/dts/a.c`))
}

func TestPathMatchOrder(t *testing.T) {
	s := &entity.Subsystem{
		PathRules: []entity.PathRule{
			{
				IncludeRegexp: `^a/b/.*$`,
				ExcludeRegexp: `^a/.*$`,
			},
		},
	}
	m := MakePathMatcher([]*entity.Subsystem{s})
	// If we first exclude a/, then a/b/c never matches.
	assert.Empty(t, m.Match("a/b/c"))
}
