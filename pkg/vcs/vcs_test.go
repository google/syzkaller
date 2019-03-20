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
		"https://chromium.googlesource.com/chromiumos/third_party/kernel":       true,
		"https://fuchsia.googlesource.com":                                      true,
		"":                                                                      false,
		"foobar":                                                                false,
		"linux-next":                                                            false,
		"foo://kernel.ubuntu.com/ubuntu/ubuntu-zesty.git":                       false,
		"git://kernel/ubuntu.git":                                               false,
		"gitgit://kernel.ubuntu.com/ubuntu/ubuntu-zesty.git":                    false,
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
		"449dd6984d0eaabbc":                        true, // 17
		"449dd6984d0eaabb":                         true, // 16
		"a4983672f9ca4c":                           true, // 14
		"449dd6984d0e":                             true, // 12
		"eae05cb0aab":                              true, // 11
		"eae05cb0aa":                               true, // 10
		"eae05cb0":                                 true, // 8
		"":                                         false,
		"aa":                                       false,
		"eae05cb":                                  false,
		"ff12bea91c22bba93d3ffc3034d813d686bc7eebb": false,
		"xxxxxxxx": false,
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

func TestCommitLink(t *testing.T) {
	type Test struct {
		URL        string
		Hash       string
		CommitLink string
	}
	tests := []Test{
		{
			"https://github.com/google/syzkaller",
			"76dd003f1b102b791d8b342a1f92a6486ff56a1e",
			"https://github.com/google/syzkaller/commit/76dd003f1b102b791d8b342a1f92a6486ff56a1e",
		},
		{
			"https://github.com/google/syzkaller.git",
			"76dd003f1b",
			"https://github.com/google/syzkaller/commit/76dd003f1b",
		},
		{
			"https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git",
			"8fe28cb58bcb",
			"https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=8fe28cb58bcb",
		},
		{
			"git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git",
			"8fe28cb58b",
			"https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=8fe28cb58b",
		},

		{
			"https://android.googlesource.com/kernel/common",
			"d0c3914ffbe4c00f0a131bae83f811d5606699bc",
			"https://android.googlesource.com/kernel/common/+/d0c3914ffbe4c00f0a131bae83f811d5606699bc^!",
		},
		{
			"https://gvisor.googlesource.com/gvisor",
			"5301cbf8430e5436211bc142c0886d8c11cc71ab",
			"https://gvisor.googlesource.com/gvisor/+/5301cbf8430e5436211bc142c0886d8c11cc71ab^!",
		},
		{
			"https://fuchsia.googlesource.com",
			"13ee3dc5e4c46bf127977ad28645c47442ec517d",
			"https://fuchsia.googlesource.com/fuchsia/+/13ee3dc5e4c46bf127977ad28645c47442ec517d^!",
		},
		{
			"git://git.cmpxchg.org/linux-mmots.git",
			"8fe28cb58b",
			"",
		},
		{
			"",
			"8fe28cb58b",
			"",
		},
		{
			"https://android.googlesource.com/kernel/common",
			"",
			"",
		},
	}
	for _, test := range tests {
		link := CommitLink(test.URL, test.Hash)
		if link != test.CommitLink {
			t.Errorf("URL: %v\nhash: %v\nwant: %v\ngot:  %v", test.URL, test.Hash, test.CommitLink, link)
		}
	}
}
