// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package linux

import (
	"testing"

	"github.com/google/syzkaller/pkg/subsystem"
)

func TestEmailToName(t *testing.T) {
	tests := map[string]string{
		// These are following the general rules.
		"linux-nilfs@vger.kernel.org":           "nilfs",
		"tomoyo-dev-en@lists.osdn.me":           "tomoyo",
		"tipc-discussion@lists.sourceforge.net": "tipc",
		"v9fs-developer@lists.sourceforge.net":  "v9fs",
		"zd1211-devs@lists.sourceforge.net":     "zd1211",
		// Test that we can handle exceptions.
		"virtualization@lists.linux-foundation.org": "virt",
	}
	for email, name := range tests {
		result := emailToName(email)
		if result != name {
			t.Fatalf("%#v: expected %#v, got %#v", email, name, result)
		}
	}
}

type subsystemTestInput struct {
	email   string
	outName string
}

func (sti subsystemTestInput) ToSubsystem() *subsystem.Subsystem {
	s := &subsystem.Subsystem{}
	if sti.email != "" {
		s.Lists = append(s.Lists, sti.email)
	}
	return s
}

func TestSetSubsystemNames(t *testing.T) {
	tests := []struct {
		name     string
		inputs   []subsystemTestInput
		mustFail bool
	}{
		{
			name: "plan test",
			inputs: []subsystemTestInput{
				{
					email:   "linux-ntfs-dev@lists.sourceforge.net",
					outName: "ntfs",
				},
				{
					email:   "llvm@lists.linux.dev",
					outName: "llvm",
				},
			},
		},
		{
			name: "has dup name",
			inputs: []subsystemTestInput{
				{
					email:   "linux-ntfs-dev@lists.sourceforge.net",
					outName: "ntfs",
				},
				{
					email:   "ntfs@lists.sourceforge.net",
					outName: "ntfs",
				},
			},
			mustFail: true,
		},
		{
			name: "has empty list",
			inputs: []subsystemTestInput{
				{
					email:   "linux-ntfs-dev@lists.sourceforge.net",
					outName: "ntfs",
				},
				{
					email:   "",
					outName: "",
				},
			},
			mustFail: true,
		},
	}
	for _, test := range tests {
		curr := test
		t.Run(curr.name, func(t *testing.T) {
			list := []*subsystem.Subsystem{}
			for _, i := range curr.inputs {
				list = append(list, i.ToSubsystem())
			}
			err := setSubsystemNames(list)
			if curr.mustFail != (err != nil) {
				t.Fatalf("expected failure: %v, got: %v", curr.mustFail, err)
			}
			if curr.mustFail {
				return
			}
			for i, item := range list {
				if item.Name != curr.inputs[i].outName {
					t.Fatalf("invalid name for #%d: expected %#v, got %#v",
						i+1, curr.inputs[i].outName, item.Name,
					)
				}
			}
		})
	}
}
