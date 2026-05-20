// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"testing"

	"github.com/google/syzkaller/pkg/kconfig"
	"gopkg.in/yaml.v3"
)

func TestReleaseTag(t *testing.T) {
	type Test struct {
		in  string
		out string
		err bool
	}
	tests := []Test{
		{
			in: `
VERSION = 4
PATCHLEVEL = 19
SUBLEVEL = 144
EXTRAVERSION =
`,
			out: "v4.19",
		},
		{
			in: `
VERSION = 5
PATCHLEVEL = 4
SUBLEVEL = 0
EXTRAVERSION =
`,
			out: "v5.4",
		},
		{
			in: `
VERSION = 5
PATCHLEVEL = 11
SUBLEVEL = 0
EXTRAVERSION = -rc3
`,
			out: "v5.11",
		},
		{
			in: `
PATCHLEVEL = 11
SUBLEVEL = 0
EXTRAVERSION = -rc3
`,
			err: true,
		},
	}
	for i, test := range tests {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			got, err := releaseTagImpl([]byte(test.in))
			if test.err != (err != nil) {
				t.Fatalf("expected err=%v, got %q", test.err, err)
			}
			if test.out != got {
				t.Fatalf("expected release %q, got %q", test.out, got)
			}
		})
	}
}

func TestParseNode(t *testing.T) {
	type Test struct {
		in          string
		name        string
		val         string
		constraints []string
		err         bool
	}
	tests := []Test{
		{
			in:   `FOO`,
			name: "FOO",
			val:  "y",
		},
		{
			in:   `FOO: 42`,
			name: "FOO",
			val:  "42",
		},
		{
			in:   `FOO: "string"`,
			name: "FOO",
			val:  `"string"`,
		},
		{
			in:   `FOO: n`,
			name: "FOO",
			val:  kconfig.No,
		},
		{
			in:   `FOO: [y]`,
			name: "FOO",
			val:  "y",
		},
		{
			in:   `FOO: [n]`,
			name: "FOO",
			val:  kconfig.No,
		},
		{
			in:   `FOO: [42]`,
			name: "FOO",
			val:  "42",
		},
		{
			in:          `FOO: [prop1, prop2]`,
			name:        "FOO",
			val:         "y",
			constraints: []string{"prop1", "prop2"},
		},
		{
			in:          `FOO: [prop1, y]`,
			name:        "FOO",
			val:         "y",
			constraints: []string{"prop1"},
		},
	}
	for i, test := range tests {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			var nodes []yaml.Node
			err := yaml.Unmarshal([]byte("- "+test.in), &nodes)
			if err != nil {
				t.Fatalf("failed to unmarshal: %v", err)
			}
			if len(nodes) != 1 {
				t.Fatalf("expected 1 node, got %v", len(nodes))
			}
			name, val, constraints, err := parseNode(nodes[0])
			if test.err != (err != nil) {
				t.Fatalf("expected err=%v, got %q", test.err, err)
			}
			if name != test.name {
				t.Fatalf("expected name %q, got %q", test.name, name)
			}
			if val != test.val {
				t.Fatalf("expected val %q, got %q", test.val, val)
			}
			if len(constraints) != len(test.constraints) {
				t.Fatalf("expected %v constraints, got %v", len(test.constraints), len(constraints))
			}
			for j, c := range constraints {
				if c != test.constraints[j] {
					t.Fatalf("expected constraint %q, got %q", test.constraints[j], c)
				}
			}
		})
	}
}
