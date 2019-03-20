// Copyright 2019 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vcs

type freebsd struct {
	*git
}

func newFreeBSD(vm, dir string) *freebsd {
	return &freebsd{
		git: newGit(dir, nil),
	}
}
