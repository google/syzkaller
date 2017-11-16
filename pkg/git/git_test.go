// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package git

import (
	"testing"
)

func TestCanonicalizeCommit(t *testing.T) {
	tests := map[string]string{
		"foo bar":                     "foo bar",
		" foo ":                       "foo",
		"UPSTREAM: foo bar":           "foo bar",
		"BACKPORT: UPSTREAM: foo bar": "UPSTREAM: foo bar",
	}
	for in, want := range tests {
		got := CanonicalizeCommit(in)
		if got != want {
			t.Errorf("input %q: got %q, want %q", in, got, want)
		}
	}
}

func TestCheckRepoAddress(t *testing.T) {
	var tests = []struct {
		repo   string
		result bool
	}{
		{"git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git", true},
		{"https://github.com/torvalds/linux.git", true},
		{"git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git", true},
		{"git://git.cmpxchg.org/linux-mmots.git", true},
		{"https://anonscm.debian.org/git/kernel/linux.git", true},
		{"git://kernel.ubuntu.com/ubuntu/ubuntu-zesty.git", true},
		{"http://host.xz:123/path/to/repo.git/", true},
		{"", false},
		{"foobar", false},
		{"linux-next", false},
		{"foo://kernel.ubuntu.com/ubuntu/ubuntu-zesty.git", false},
		{"git://kernel/ubuntu.git", false},
		{"git://kernel.com/ubuntu", false},
		{"gitgit://kernel.ubuntu.com/ubuntu/ubuntu-zesty.git", false},
	}
	for _, test := range tests {
		res := CheckRepoAddress(test.repo)
		if res != test.result {
			t.Errorf("%v: got %v, want %v", test.repo, res, test.result)
		}
	}
}

func TestCheckBranch(t *testing.T) {
	var tests = []struct {
		branch string
		result bool
	}{
		{"master", true},
		{"core/core", true},
		{"irq-irqdomain-for-linus", true},
		{"timers/2038", true},
		{"ubuntu-zesty/v4.9.4", true},
		{"WIP.locking/atomics", true},
		{"linux-4.9.y", true},
		{"abi_spec", true},
		{"@", false},
	}
	for _, test := range tests {
		res := CheckBranch(test.branch)
		if res != test.result {
			t.Errorf("%v: got %v, want %v", test.branch, res, test.result)
		}
	}
}
