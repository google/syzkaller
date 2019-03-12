// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vcs

type openbsd struct {
	*git
}

func newOpenBSD(vm, dir string) *openbsd {
	return &openbsd{
		git: newGit(dir, nil),
	}
}
