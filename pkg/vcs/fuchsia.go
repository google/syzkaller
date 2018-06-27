// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vcs

import (
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/google/syzkaller/pkg/osutil"
)

type fuchsia struct {
	vm     string
	dir    string
	zircon *git
}

func newFuchsia(vm, dir string) *fuchsia {
	return &fuchsia{
		vm:     vm,
		dir:    dir,
		zircon: newGit("fuchsia", vm, filepath.Join(dir, "zircon")),
	}
}

// mkdir DIR; cd DIR
// curl -s "https://fuchsia.googlesource.com/scripts/+/master/bootstrap?format=TEXT" | base64 --decode | bash -s topaz
// (cd fuchsia && .jiri_root/bin/jiri update)
// (cd fuchsia/zircon/ && git show HEAD)

func (fu *fuchsia) Poll(repo, branch string) (*Commit, error) {
	if repo != "https://fuchsia.googlesource.com" || branch != "master" {
		// fuchsia ecosystem is hard-tailored to the main repo.
		return nil, fmt.Errorf("fuchsia: can only check out https://fuchsia.googlesource.com/master")
	}
	if _, err := runSandboxed(fu.dir, "./.jiri_root/bin/jiri", "update"); err != nil {
		if err := fu.initRepo(); err != nil {
			return nil, err
		}
	}
	return fu.zircon.HeadCommit()
}

func (fu *fuchsia) initRepo() error {
	if err := os.RemoveAll(fu.dir); err != nil {
		return fmt.Errorf("failed to remove repo dir: %v", err)
	}
	tmpDir := fu.dir + ".tmp"
	if err := osutil.MkdirAll(tmpDir); err != nil {
		return fmt.Errorf("failed to create repo dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)
	cmd := "curl -s 'https://fuchsia.googlesource.com/scripts/+/master/bootstrap?format=TEXT' |" +
		"base64 --decode | bash -s topaz"
	if _, err := runSandboxed(tmpDir, "bash", "-c", cmd); err != nil {
		return err
	}
	return os.Rename(filepath.Join(tmpDir, "fuchsia"), fu.dir)
}

func (fu *fuchsia) CheckoutBranch(repo, branch string) (*Commit, error) {
	return nil, fmt.Errorf("not implemented for fuchsia")
}

func (fu *fuchsia) CheckoutCommit(repo, commit string) (*Commit, error) {
	return nil, fmt.Errorf("not implemented for fuchsia")
}

func (fu *fuchsia) SwitchCommit(commit string) (*Commit, error) {
	return nil, fmt.Errorf("not implemented for fuchsia")
}

func (fu *fuchsia) HeadCommit() (*Commit, error) {
	return nil, fmt.Errorf("not implemented for fuchsia")
}

func (fu *fuchsia) ListRecentCommits(baseCommit string) ([]string, error) {
	return nil, nil
}

func (fu *fuchsia) ExtractFixTagsFromCommits(baseCommit, email string) ([]FixCommit, error) {
	return nil, fmt.Errorf("not implemented for fuchsia")
}

func (fu *fuchsia) Bisect(bad, good string, trace io.Writer, pred func() (BisectResult, error)) (*Commit, error) {
	return nil, fmt.Errorf("not implemented for fuchsia")
}

func (fu *fuchsia) PreviousReleaseTags(commit string) ([]string, error) {
	return nil, fmt.Errorf("not implemented for fuchsia")
}
