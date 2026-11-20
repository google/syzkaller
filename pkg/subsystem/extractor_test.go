// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package subsystem

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtractor(t *testing.T) {
	// Objects used in tests.
	fsPath, mmFsPath := "fs/", "mm/fs.c"
	extProg, nfsProg, extNfsProg := []byte("ext"), []byte("nfs"), []byte("ext nfs")
	all := &Subsystem{Name: "fs"}
	fs := &Subsystem{Name: "fs", Parents: []*Subsystem{all}}
	ext := &Subsystem{Name: "ext", Parents: []*Subsystem{fs}}
	nfs := &Subsystem{Name: "nfs", Parents: []*Subsystem{fs}}
	mm := &Subsystem{Name: "mm", Parents: []*Subsystem{all}}
	// Tests themselves.
	tests := []struct {
		name    string
		crashes []*Crash
		want    []*Subsystem
	}{
		{
			name: `Make sure it works fine with just a single path`,
			crashes: []*Crash{
				{
					GuiltyPath: fsPath,
				},
			},
			want: []*Subsystem{fs},
		},
		{
			name: `Make sure a child shadows its parent`,
			crashes: []*Crash{
				{
					GuiltyPath: fsPath,
				},
				{
					GuiltyPath: fsPath,
					SyzRepro:   extProg,
				},
			},
			want: []*Subsystem{ext},
		},
		{
			name: `Reproducers hint at different subsystems`,
			crashes: []*Crash{
				{
					GuiltyPath: fsPath,
				},
				{
					GuiltyPath: fsPath,
					SyzRepro:   extProg,
				},
				{
					GuiltyPath: fsPath,
					SyzRepro:   nfsProg,
				},
			},
			want: []*Subsystem{fs},
		},
		{
			name: `One subsystem from reproducers is irrelevant`,
			crashes: []*Crash{
				{
					GuiltyPath: fsPath,
				},
				{
					GuiltyPath: fsPath,
					SyzRepro:   extProg,
				},
				{
					GuiltyPath: fsPath,
					SyzRepro:   extNfsProg,
				},
			},
			want: []*Subsystem{ext},
		},
		{
			name: `Reproducer supporting one of guilty paths`,
			crashes: []*Crash{
				// The guilty paths correspond both to mm and fs.
				{
					GuiltyPath: mmFsPath,
				},
				{
					GuiltyPath: mmFsPath,
				},
				{
					GuiltyPath: mmFsPath,
				},
				{
					// But one reproducer points clearly to fs.
					GuiltyPath: mmFsPath,
					SyzRepro:   extProg,
				},
			},
			want: []*Subsystem{ext},
		},
	}
	extractor := &Extractor{
		raw: &testRawExtractor{
			perPath: map[string][]*Subsystem{
				fsPath:   {fs},
				mmFsPath: {mm, fs},
			},
			perProg: []progSubsystems{
				{extProg, []*Subsystem{ext}},
				{nfsProg, []*Subsystem{nfs}},
				{extNfsProg, []*Subsystem{ext, nfs}},
			},
		},
	}
	for _, test := range tests {
		ret := extractor.Extract(test.crashes)
		assert.ElementsMatch(t, ret, test.want, test.name)
	}
}

func TestExtractFromPaths(t *testing.T) {
	all := &Subsystem{Name: "all"}
	fs := &Subsystem{Name: "fs", Parents: []*Subsystem{all}}
	ext := &Subsystem{Name: "ext", Parents: []*Subsystem{fs}}
	mm := &Subsystem{Name: "mm", Parents: []*Subsystem{all}}

	extractor := &Extractor{
		raw: &testRawExtractor{
			perPath: map[string][]*Subsystem{
				"":                {all},
				"fs/open.c":       {fs, all},
				"fs/ext4/inode.c": {ext, fs},
				"fs/ext4/super.c": {ext, fs},
				"mm/slub.c":       {mm, all},
			},
		},
	}

	tests := []struct {
		name  string
		paths []string
		want  []*Subsystem
	}{
		{
			name:  "single path collapses parents",
			paths: []string{"fs/ext4/inode.c"},
			want:  []*Subsystem{ext},
		},
		{
			name:  "duplicate subsystems deduplicated",
			paths: []string{"fs/ext4/inode.c", "fs/ext4/super.c"},
			want:  []*Subsystem{ext},
		},
		{
			name:  "child shadows parent across paths",
			paths: []string{"fs/open.c", "fs/ext4/inode.c"},
			want:  []*Subsystem{ext},
		},
		{
			name:  "multiple unrelated subsystems preserved",
			paths: []string{"fs/ext4/inode.c", "mm/slub.c"},
			want:  []*Subsystem{ext, mm},
		},
		{
			name:  "unmatched or empty paths return empty",
			paths: []string{"", "unknown/file.c"},
			want:  nil,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ret := extractor.ExtractFromPaths(test.paths)
			assert.ElementsMatch(t, test.want, ret)
		})
	}
}

type testRawExtractor struct {
	perPath map[string][]*Subsystem
	perProg []progSubsystems
}

type progSubsystems struct {
	prog []byte
	ret  []*Subsystem
}

func (e *testRawExtractor) FromPath(path string) []*Subsystem {
	return e.perPath[path]
}

func (e *testRawExtractor) FromProg(progBytes []byte) []*Subsystem {
	for _, obj := range e.perProg {
		if reflect.DeepEqual(progBytes, obj.prog) {
			return obj.ret
		}
	}
	return nil
}
