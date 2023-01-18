// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package linux

import (
	"testing"
	"testing/fstest"

	"github.com/google/syzkaller/pkg/subsystem/entity"
	"github.com/google/syzkaller/pkg/subsystem/match"
	"github.com/stretchr/testify/assert"
)

func TestLoopsDoExist(t *testing.T) {
	a := &entity.Subsystem{}
	b := &entity.Subsystem{Parents: []*entity.Subsystem{a}}
	c := &entity.Subsystem{Parents: []*entity.Subsystem{b}}
	a.Parents = []*entity.Subsystem{c}
	assert.True(t, loopsExist([]*entity.Subsystem{a, b, c}))
}

func TestLoopsDoNotExist(t *testing.T) {
	a := &entity.Subsystem{}
	b := &entity.Subsystem{Parents: []*entity.Subsystem{a}}
	c := &entity.Subsystem{Parents: []*entity.Subsystem{b}}
	assert.False(t, loopsExist([]*entity.Subsystem{a, b, c}))
}

func TestTransitiveReduction(t *testing.T) {
	// (d, c), (c, b), (b, a)
	// (d, a)
	// (d, b)
	// (d, e)
	// (c, a)
	a := &entity.Subsystem{}
	b := &entity.Subsystem{Parents: []*entity.Subsystem{a}}
	c := &entity.Subsystem{Parents: []*entity.Subsystem{a, b}}
	e := &entity.Subsystem{}
	d := &entity.Subsystem{Parents: []*entity.Subsystem{a, b, c, e}}
	transitiveReduction([]*entity.Subsystem{a, b, c, d, e})

	// The result should be:
	// (d, c), (c, b), (b, a)
	// (d, e)
	assert.ElementsMatch(t, d.Parents, []*entity.Subsystem{c, e})
	assert.ElementsMatch(t, c.Parents, []*entity.Subsystem{b})
}

func TestSetParents(t *testing.T) {
	kernel := &entity.Subsystem{PathRules: []entity.PathRule{{
		IncludeRegexp: `.*`,
	}}}
	net := &entity.Subsystem{PathRules: []entity.PathRule{{
		IncludeRegexp: `^net/`,
	}}}
	wireless := &entity.Subsystem{PathRules: []entity.PathRule{{
		IncludeRegexp: `^net/wireless`,
	}}}
	drivers := &entity.Subsystem{PathRules: []entity.PathRule{{
		IncludeRegexp: `^drivers/`,
	}}}

	tree := fstest.MapFS{
		"include/net/cfg80211.h":   {},
		"net/socket.c":             {},
		"net/nfc/core.c":           {},
		"net/wireless/nl80211.c":   {},
		"net/wireless/sysfs.c":     {},
		"net/ipv4/arp.c":           {},
		"drivers/usb/host/xhci.c":  {},
		"drivers/android/binder.c": {},
	}

	matrix, err := match.BuildCoincidenceMatrix(tree,
		[]*entity.Subsystem{kernel, net, wireless, drivers}, nil)
	assert.NoError(t, err)

	// Calculate parents.
	err = SetParents(matrix, []*entity.Subsystem{kernel, net, wireless, drivers})
	if err != nil {
		t.Fatal(err)
	}

	// Verify parents.
	assert.ElementsMatch(t, net.Parents, []*entity.Subsystem{kernel})
	assert.ElementsMatch(t, wireless.Parents, []*entity.Subsystem{net})
	assert.ElementsMatch(t, drivers.Parents, []*entity.Subsystem{kernel})
	assert.ElementsMatch(t, kernel.Parents, []*entity.Subsystem{})
}
