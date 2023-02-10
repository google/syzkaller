// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package linux

import (
	"testing"
	"testing/fstest"

	"github.com/google/syzkaller/pkg/subsystem"
	"github.com/stretchr/testify/assert"
)

func TestBuildCoincidenceMatrix(t *testing.T) {
	vfs := &subsystem.Subsystem{PathRules: []subsystem.PathRule{
		{IncludeRegexp: `^fs/`},
	}}
	ext4 := &subsystem.Subsystem{PathRules: []subsystem.PathRule{
		{IncludeRegexp: `^fs/ext4/`},
	}}
	ntfs := &subsystem.Subsystem{PathRules: []subsystem.PathRule{
		{IncludeRegexp: `^fs/ntfs/`},
	}}
	kernel := &subsystem.Subsystem{PathRules: []subsystem.PathRule{
		{IncludeRegexp: `.*`},
	}}

	fs := fstest.MapFS{
		".git/obj/12345": {},
		"fs/inode.c":     {},
		"fs/ext4/file.c": {},
		"fs/ntfs/file.c": {},
		"fs/fat/file.c":  {},
		"net/socket.c":   {},
	}
	matrix, err := BuildCoincidenceMatrix(fs, []*subsystem.Subsystem{vfs, ntfs, ext4, kernel}, nil)
	assert.NoError(t, err)

	// Test total counts.
	assert.Equal(t, 5, matrix.Count(kernel))
	assert.Equal(t, 4, matrix.Count(vfs))
	assert.Equal(t, 1, matrix.Count(ext4))

	// Test pairwise counts.
	assert.Equal(t, 1, matrix.Get(vfs, ext4))
	assert.Equal(t, 1, matrix.Get(vfs, ntfs))
	assert.Equal(t, 0, matrix.Get(ext4, ntfs))
	assert.Equal(t, 4, matrix.Get(kernel, vfs))
}
