// Copyright 2019 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vcs

import (
	"bytes"
	"io"
	"net/mail"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/email"
	"github.com/google/syzkaller/pkg/osutil"
)

type linux struct {
	*git
}

func newLinux(dir string) *linux {
	ignoreCC := map[string]bool{
		"stable@vger.kernel.org": true,
	}
	return &linux{
		git: newGit(dir, ignoreCC),
	}
}

func (ctx *linux) Bisect(bad, good string, trace io.Writer, pred func() (BisectResult, error)) ([]*Commit, error) {
	commits, err := ctx.git.Bisect(bad, good, trace, pred)
	if len(commits) == 1 {
		ctx.addMaintainers(commits[0])
	}
	return commits, err
}

func (ctx *linux) addMaintainers(com *Commit) {
	if len(com.CC) > 3 {
		return
	}
	list := ctx.getMaintainers(com.Hash, false)
	if len(list) < 3 {
		list = ctx.getMaintainers(com.Hash, true)
	}
	com.CC = email.MergeEmailLists(com.CC, list)
}

func (ctx *linux) getMaintainers(hash string, blame bool) []string {
	args := "git show " + hash + " | " +
		filepath.FromSlash("scripts/get_maintainer.pl") + " --no-n --no-rolestats"
	if blame {
		args += " --git-blame"
	}
	output, err := osutil.RunCmd(time.Minute, ctx.git.dir, "bash", "-c", args)
	if err != nil {
		return nil
	}
	var list []string
	for _, line := range strings.Split(string(output), "\n") {
		addr, err := mail.ParseAddress(line)
		if err != nil {
			continue
		}
		list = append(list, strings.ToLower(addr.Address))
	}
	return list
}

func (ctx *linux) PreviousReleaseTags(commit string) ([]string, error) {
	output, err := runSandboxed(ctx.dir, "git", "tag", "--no-contains", commit, "--merged", commit, "v*.*")
	if err != nil {
		return nil, err
	}
	tags, err := gitParseReleaseTags(output)
	if err != nil {
		return nil, err
	}
	for i, tag := range tags {
		if tag == "v3.8" {
			// v3.8 does not work with modern perl, and as we go further in history
			// make stops to work, then binutils, glibc, etc. So we stop at v3.8.
			// Up to that point we only need an ancient gcc.
			tags = tags[:i]
			break
		}
	}
	return tags, nil
}

func gitParseReleaseTags(output []byte) ([]string, error) {
	var tags []string
	for _, tag := range bytes.Split(output, []byte{'\n'}) {
		if releaseTagRe.Match(tag) && gitReleaseTagToInt(string(tag)) != 0 {
			tags = append(tags, string(tag))
		}
	}
	sort.Slice(tags, func(i, j int) bool {
		return gitReleaseTagToInt(tags[i]) > gitReleaseTagToInt(tags[j])
	})
	return tags, nil
}

func gitReleaseTagToInt(tag string) uint64 {
	matches := releaseTagRe.FindStringSubmatchIndex(tag)
	v1, err := strconv.ParseUint(tag[matches[2]:matches[3]], 10, 64)
	if err != nil {
		return 0
	}
	v2, err := strconv.ParseUint(tag[matches[4]:matches[5]], 10, 64)
	if err != nil {
		return 0
	}
	var v3 uint64
	if matches[6] != -1 {
		v3, err = strconv.ParseUint(tag[matches[6]:matches[7]], 10, 64)
		if err != nil {
			return 0
		}
	}
	return v1*1e6 + v2*1e3 + v3
}

func (ctx *linux) EnvForCommit(commit string, kernelConfig []byte) (*BisectEnv, error) {
	tagList, err := ctx.PreviousReleaseTags(commit)
	if err != nil {
		return nil, err
	}
	tags := make(map[string]bool)
	for _, tag := range tagList {
		tags[tag] = true
	}
	env := &BisectEnv{
		Compiler:     "gcc-" + linuxCompilerVersion(tags),
		KernelConfig: kernelConfig,
	}
	return env, nil
}

func linuxCompilerVersion(tags map[string]bool) string {
	switch {
	case tags["v4.12"]:
		return "8.1.0"
	case tags["v4.11"]:
		return "7.3.0"
	case tags["v3.19"]:
		return "5.5.0"
	default:
		return "4.9.4"
	}
}
