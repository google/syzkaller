// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vcs

import (
	"io/fs"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/osutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClangVersion(t *testing.T) {
	defaultCompiler := "/some/default/compiler"
	binDir := "/some/dir/"
	tags := make(map[string]bool)

	// No tags case.
	actual := linuxClangPath(tags, binDir, defaultCompiler)
	expected := binDir + "llvm-9.0.1/bin/clang"
	assert.Equal(t, actual, expected, "unexpected clang path")

	// Older tag case.
	tags["v5.9"] = true
	actual = linuxClangPath(tags, binDir, defaultCompiler)
	expected = "clang-15"
	assert.Equal(t, actual, expected, "unexpected clang path")

	// Recent tag case.
	tags["v6.15"] = true
	actual = linuxClangPath(tags, binDir, defaultCompiler)
	expected = defaultCompiler
	assert.Equal(t, actual, expected, "unexpected clang path")
}

func TestGCCVersion(t *testing.T) {
	defaultCompiler := "/some/default/compiler"
	binDir := "/some/dir/"
	tags := make(map[string]bool)

	// No tags case.
	actual := linuxGCCPath(tags, binDir, defaultCompiler)
	expected := binDir + "gcc-5.5.0/bin/gcc"
	assert.Equal(t, actual, expected, "unexpected gcc path")

	// Somewhat old tag case.
	tags["v4.12"] = true
	actual = linuxGCCPath(tags, binDir, defaultCompiler)
	expected = binDir + "gcc-8.1.0/bin/gcc"
	assert.Equal(t, actual, expected, "unexpected gcc path")

	// Recent tag case.
	tags["v5.16"] = true
	actual = linuxGCCPath(tags, binDir, defaultCompiler)
	expected = defaultCompiler
	assert.Equal(t, actual, expected, "unexpected gcc path")
}

func TestGetMaintainersSharedClone(t *testing.T) {
	osutil.RequireSandbox(t)
	originDir := osutil.SandboxTempDir(t)
	origin := MakeTestRepo(t, originDir)
	scriptRel := filepath.FromSlash("scripts/get_maintainer.pl")
	script := `#!/bin/sh
set -eu
! touch escape 2>/dev/null
! touch .git/escape 2>/dev/null
! touch ../.git/escape 2>/dev/null
cat >/dev/null
git log -1 --format='%an <%ae> (maintainer:TEST)'
`
	require.NoError(t, osutil.MkdirAll(filepath.Join(originDir, "scripts")))
	require.NoError(t, osutil.WriteExecFile(filepath.Join(originDir, scriptRel), []byte(script)))
	subScriptRel := filepath.FromSlash("sub/scripts/get_maintainer.pl")
	require.NoError(t, osutil.MkdirAll(filepath.Join(originDir, "sub", "scripts")))
	require.NoError(t, osutil.WriteExecFile(filepath.Join(originDir, subScriptRel), []byte(script)))
	require.NoError(t, osutil.SandboxChown(
		filepath.Join(originDir, "scripts"), filepath.Join(originDir, scriptRel),
		filepath.Join(originDir, "sub"), filepath.Join(originDir, "sub", "scripts"),
		filepath.Join(originDir, subScriptRel),
	))
	origin.Git("add", scriptRel, subScriptRel)
	com := origin.CommitChange("add fake get_maintainer.pl")

	cloneDir := osutil.SandboxTempDir(t)
	_, err := osutil.RunCmd(time.Minute, "", "git", "clone", "--shared", originDir, cloneDir)
	require.NoError(t, err)
	require.NoError(t, filepath.WalkDir(cloneDir, func(p string, _ fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		return osutil.SandboxChown(p)
	}))

	lnx := newLinux(cloneDir, nil, "")
	mtrs := lnx.getMaintainers(com.Hash, false)
	require.Len(t, mtrs, 1)
	assert.Equal(t, userEmail, mtrs[0].Address.Address)

	// Subdirectory checkout (KernelSrcSuffix) must still find enclosing .git and shared alternates.
	subMtrs, err := RunGetMaintainer(filepath.Join(cloneDir, "sub"), strings.NewReader(""), nil)
	require.NoError(t, err)
	require.Len(t, subMtrs, 1)
	assert.Equal(t, userEmail, subMtrs[0].Address.Address)
}
