// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vcs

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
	testPredicate(t, CheckRepoAddress, map[string]bool{
		"git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git":      true,
		"https://github.com/torvalds/linux.git":                                 true,
		"git://git.kernel.org/pub/scm/linux/kernel/git/stable/linux-stable.git": true,
		"git://git.cmpxchg.org/linux-mmots.git":                                 true,
		"https://anonscm.debian.org/git/kernel/linux.git":                       true,
		"git://kernel.ubuntu.com/ubuntu/ubuntu-zesty.git":                       true,
		"http://host.xz:123/path/to/repo.git/":                                  true,
		"":           false,
		"foobar":     false,
		"linux-next": false,
		"foo://kernel.ubuntu.com/ubuntu/ubuntu-zesty.git":    false,
		"git://kernel/ubuntu.git":                            false,
		"git://kernel.com/ubuntu":                            false,
		"gitgit://kernel.ubuntu.com/ubuntu/ubuntu-zesty.git": false,
	})
}

func TestCheckBranch(t *testing.T) {
	testPredicate(t, CheckBranch, map[string]bool{
		"master":                  true,
		"core/core":               true,
		"irq-irqdomain-for-linus": true,
		"timers/2038":             true,
		"ubuntu-zesty/v4.9.4":     true,
		"WIP.locking/atomics":     true,
		"linux-4.9.y":             true,
		"abi_spec":                true,
		"@":                       false,
		"":                        false,
	})
}

func TestCheckCommitHash(t *testing.T) {
	testPredicate(t, CheckCommitHash, map[string]bool{
		"ff12bea91c22bba93d3ffc3034d813d686bc7eeb": true, // 40
		"eae05cb0aaeae05cb0aa":                     true, // 20
		"449dd6984d0eaabb":                         true, // 16
		"449dd6984d0e":                             true, // 12
		"eae05cb0aa":                               true, // 10
		"eae05cb0":                                 true, // 8
		"":                                         false,
		"aa":                                       false,
		"eae05cb0aab":                              false,
		"xxxxxxxx":                                 false,
	})
}

func testPredicate(t *testing.T, fn func(string) bool, tests map[string]bool) {
	for input, want := range tests {
		res := fn(input)
		if res != want {
			t.Errorf("%v: got %v, want %v", input, res, want)
		}
	}
}
