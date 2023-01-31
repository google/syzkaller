// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package subsystem

import (
	"reflect"
	"testing"

	"github.com/google/syzkaller/pkg/subsystem/entity"
	"github.com/stretchr/testify/assert"
)

func TestExtractor(t *testing.T) {
	// Objects used in tests.
	fsPath := "fs/"
	extProg, nfsProg := []byte("ext prog"), []byte("nfs prog")
	fs := &entity.Subsystem{Name: "fs"}
	ext := &entity.Subsystem{Name: "ext", Parents: []*entity.Subsystem{fs}}
	nfs := &entity.Subsystem{Name: "nfs", Parents: []*entity.Subsystem{fs}}
	// Tests themselves.
	tests := []struct {
		name    string
		crashes []*Crash
		want    []*entity.Subsystem
	}{
		{
			name: `Make sure it works fine with just a single path`,
			crashes: []*Crash{
				{
					GuiltyPath: fsPath,
				},
			},
			want: []*entity.Subsystem{fs},
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
			want: []*entity.Subsystem{ext},
		},
		{
			name: `Two equally present children`,
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
			want: []*entity.Subsystem{nfs, ext},
		},
		{
			name: `One child is more present than another`,
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
				{
					GuiltyPath: fsPath,
					SyzRepro:   extProg,
				},
			},
			want: []*entity.Subsystem{ext},
		},
	}
	extractor := &Extractor{
		raw: &testRawExtractor{
			perPath: map[string][]*entity.Subsystem{
				fsPath: {fs},
			},
			perProg: []progSubsystems{
				{extProg, []*entity.Subsystem{ext}},
				{nfsProg, []*entity.Subsystem{nfs}},
			},
		},
	}
	for _, test := range tests {
		ret := extractor.Extract(test.crashes)
		assert.ElementsMatch(t, ret, test.want, test.name)
	}
}

type testRawExtractor struct {
	perPath map[string][]*entity.Subsystem
	perProg []progSubsystems
}

type progSubsystems struct {
	prog []byte
	ret  []*entity.Subsystem
}

func (e *testRawExtractor) FromPath(path string) []*entity.Subsystem {
	return e.perPath[path]
}

func (e *testRawExtractor) FromProg(progBytes []byte) []*entity.Subsystem {
	for _, obj := range e.perProg {
		if reflect.DeepEqual(progBytes, obj.prog) {
			return obj.ret
		}
	}
	return nil
}
