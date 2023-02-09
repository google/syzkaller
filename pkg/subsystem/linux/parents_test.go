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

func TestDropSmallSubsystems(t *testing.T) {
	kernel := &entity.Subsystem{}
	net := &entity.Subsystem{}
	fs := &entity.Subsystem{}
	legal := &entity.Subsystem{}

	matrix := match.MakeCoincidenceMatrix()
	matrix.Record(kernel, net)
	matrix.Record(kernel, fs)
	matrix.Record(kernel, net, fs)
	matrix.Record(kernel, net, fs)
	matrix.Record(kernel, net, fs)

	ret := dropSmallSubsystems(matrix, []*entity.Subsystem{kernel, net, fs, legal})
	assert.ElementsMatch(t, []*entity.Subsystem{kernel, net, fs}, ret)
}

func TestDropDuplicateSubsystems(t *testing.T) {
	input, expected := []*entity.Subsystem{}, []*entity.Subsystem{}
	matrix := match.MakeCoincidenceMatrix()

	// Always present.
	kernel := &entity.Subsystem{Name: "kernel"}
	input = append(input, kernel)
	expected = append(expected, kernel)

	// Fully overlap.
	sameA, sameB := &entity.Subsystem{Name: "SameA"}, &entity.Subsystem{Name: "SameB"}
	matrix.Record(kernel, sameA, sameB)
	matrix.Record(kernel, sameA, sameB)
	matrix.Record(kernel, sameA, sameB)
	input = append(input, sameA, sameB)
	expected = append(expected, sameA)

	// Overlap, but the smaller one is not so significant.
	ext4, fs := &entity.Subsystem{Name: "ext4"}, &entity.Subsystem{Name: "fs"}
	matrix.Record(kernel, ext4, fs)
	matrix.Record(kernel, ext4, fs)
	matrix.Record(kernel, fs) // 66%.
	input = append(input, ext4, fs)
	expected = append(expected, ext4, fs)

	// Overlap, and the smaller one takes a big part.
	toDrop, stays := &entity.Subsystem{Name: "to-drop"}, &entity.Subsystem{Name: "stays"}
	for i := 0; i < 5; i++ {
		matrix.Record(kernel, toDrop, stays)
	}
	matrix.Record(kernel, stays)
	input = append(input, toDrop, stays)
	expected = append(expected, stays)

	// Run the analysis.
	ret := dropDuplicateSubsystems(matrix, input)
	assert.ElementsMatch(t, ret, expected)
}

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

	err = setParents(matrix, []*entity.Subsystem{kernel, net, wireless, drivers})
	if err != nil {
		t.Fatal(err)
	}

	// Verify parents.
	assert.ElementsMatch(t, net.Parents, []*entity.Subsystem{kernel})
	assert.ElementsMatch(t, wireless.Parents, []*entity.Subsystem{net})
	assert.ElementsMatch(t, drivers.Parents, []*entity.Subsystem{kernel})
	assert.ElementsMatch(t, kernel.Parents, []*entity.Subsystem{})
}
