// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package linux

import (
	"testing"
	"testing/fstest"

	"github.com/google/syzkaller/pkg/subsystem"
	"github.com/stretchr/testify/assert"
)

func TestDropSmallSubsystems(t *testing.T) {
	kernel := &subsystem.Subsystem{}
	net := &subsystem.Subsystem{}
	fs := &subsystem.Subsystem{}
	legal := &subsystem.Subsystem{}

	matrix := MakeCoincidenceMatrix()
	matrix.Record(kernel, net)
	matrix.Record(kernel, fs)
	matrix.Record(kernel, net, fs)
	matrix.Record(kernel, net, fs)
	matrix.Record(kernel, net, fs)

	ret := dropSmallSubsystems(matrix, []*subsystem.Subsystem{kernel, net, fs, legal})
	assert.ElementsMatch(t, []*subsystem.Subsystem{kernel, net, fs}, ret)
}

func TestDropDuplicateSubsystems(t *testing.T) {
	input, expected := []*subsystem.Subsystem{}, []*subsystem.Subsystem{}
	matrix := MakeCoincidenceMatrix()

	// Always present.
	kernel := &subsystem.Subsystem{Name: "kernel"}
	input = append(input, kernel)
	expected = append(expected, kernel)

	// Fully overlap.
	sameA := &subsystem.Subsystem{Lists: []string{"SameA@gmail.com"}}
	sameB := &subsystem.Subsystem{Lists: []string{"SameB@gmail.com"}}
	matrix.Record(kernel, sameA, sameB)
	matrix.Record(kernel, sameA, sameB)
	matrix.Record(kernel, sameA, sameB)
	input = append(input, sameA, sameB)
	expected = append(expected, sameA)

	// Overlap, but the smaller one is not so significant.
	ext4, fs := &subsystem.Subsystem{Name: "ext4"}, &subsystem.Subsystem{Name: "fs"}
	matrix.Record(kernel, ext4, fs)
	matrix.Record(kernel, ext4, fs)
	matrix.Record(kernel, fs) // 66%.
	input = append(input, ext4, fs)
	expected = append(expected, ext4, fs)

	// Overlap, and the smaller one takes a big part.
	toDrop, stays := &subsystem.Subsystem{Name: "to-drop"}, &subsystem.Subsystem{Name: "stays"}
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

func TestTransitiveReduction(t *testing.T) {
	// (d, c), (c, b), (b, a)
	// (d, a)
	// (d, b)
	// (d, e)
	// (c, a)
	a := &subsystem.Subsystem{}
	b := &subsystem.Subsystem{Parents: []*subsystem.Subsystem{a}}
	c := &subsystem.Subsystem{Parents: []*subsystem.Subsystem{a, b}}
	e := &subsystem.Subsystem{}
	d := &subsystem.Subsystem{Parents: []*subsystem.Subsystem{a, b, c, e}}
	transitiveReduction([]*subsystem.Subsystem{a, b, c, d, e})

	// The result should be:
	// (d, c), (c, b), (b, a)
	// (d, e)
	assert.ElementsMatch(t, d.Parents, []*subsystem.Subsystem{c, e})
	assert.ElementsMatch(t, c.Parents, []*subsystem.Subsystem{b})
}

func TestSetParents(t *testing.T) {
	kernel := &subsystem.Subsystem{PathRules: []subsystem.PathRule{{
		IncludeRegexp: `.*`,
	}}}
	net := &subsystem.Subsystem{PathRules: []subsystem.PathRule{{
		IncludeRegexp: `^net/`,
	}}}
	wireless := &subsystem.Subsystem{PathRules: []subsystem.PathRule{{
		IncludeRegexp: `^net/wireless`,
	}}}
	drivers := &subsystem.Subsystem{PathRules: []subsystem.PathRule{{
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

	matrix, err := BuildCoincidenceMatrix(tree,
		[]*subsystem.Subsystem{kernel, net, wireless, drivers}, nil)
	assert.NoError(t, err)

	// Calculate parents.

	err = setParents(matrix, []*subsystem.Subsystem{kernel, net, wireless, drivers})
	if err != nil {
		t.Fatal(err)
	}

	// Verify parents.
	assert.ElementsMatch(t, net.Parents, []*subsystem.Subsystem{kernel})
	assert.ElementsMatch(t, wireless.Parents, []*subsystem.Subsystem{net})
	assert.ElementsMatch(t, drivers.Parents, []*subsystem.Subsystem{kernel})
	assert.ElementsMatch(t, kernel.Parents, []*subsystem.Subsystem{})
}
