// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package git

import (
	"reflect"
	"strings"
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
		{"", false},
	}
	for _, test := range tests {
		res := CheckBranch(test.branch)
		if res != test.result {
			t.Errorf("%v: got %v, want %v", test.branch, res, test.result)
		}
	}
}

func TestCheckCommitHash(t *testing.T) {
	var tests = []struct {
		hash   string
		result bool
	}{
		{"ff12bea91c22bba93d3ffc3034d813d686bc7eeb", true}, // 40
		{"eae05cb0aaeae05cb0aa", true},                     // 20
		{"449dd6984d0eaabb", true},                         // 16
		{"449dd6984d0e", true},                             // 12
		{"eae05cb0aa", true},                               // 10
		{"eae05cb0", true},                                 // 8
		{"", false},
		{"aa", false},
		{"eae05cb0aab", false},
		{"xxxxxxxx", false},
	}
	for _, test := range tests {
		res := CheckCommitHash(test.hash)
		if res != test.result {
			t.Errorf("%v: got %v, want %v", test.hash, res, test.result)
		}
	}
}

func TestExtractFixTags(t *testing.T) {
	commits, err := extractFixTags(strings.NewReader(extractFixTagsInput), extractFixTagsEmail)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(commits, extractFixTagsOutput) {
		t.Fatalf("got : %+v\twant: %+v", commits, extractFixTagsOutput)
	}
}

const extractFixTagsEmail = "\"syzbot\" <syzbot@my.mail.com>"

var extractFixTagsOutput = []FixCommit{
	{"8e4090902540da8c6e8f", "dashboard/app: bump max repros per bug to 10"},
	{"8e4090902540da8c6e8f", "executor: remove dead code"},
	{"a640a0fc325c29c3efcb", "executor: remove dead code"},
	{"8e4090902540da8c6e8fa640a0fc325c29c3efcb", "pkg/csource: fix string escaping bug"},
}

var extractFixTagsInput = `
commit 73aba437a774237b1130837b856f3b40b3ec3bf0 (HEAD -> master, origin/master)
Author: me <foo@bar.com>
Date:   Fri Dec 22 19:59:56 2017 +0100

    dashboard/app: bump max repros per bug to 10
    
    Reported-by: syzbot+8e4090902540da8c6e8f@my.mail.com

commit 26cd53f078db858a6ccca338e13e7f4d1d291c22
Author: me <foo@bar.com>
Date:   Fri Dec 22 13:42:27 2017 +0100

    executor: remove dead code
    
    Reported-by: syzbot+8e4090902540da8c6e8f@my.mail.com
    Reported-by: syzbot <syzbot+a640a0fc325c29c3efcb@my.mail.com>

commit 7b62abdb0abadbaf7b3f3a23ab4d78485fbf9059
Author: Dmitry Vyukov <dvyukov@google.com>
Date:   Fri Dec 22 11:59:09 2017 +0100

    pkg/csource: fix string escaping bug
    
    Reported-and-tested-by: syzbot+8e4090902540da8c6e8fa640a0fc325c29c3efcb@my.mail.com
`
