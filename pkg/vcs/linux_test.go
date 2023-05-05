// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vcs

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestClangVersion(t *testing.T) {
	defaultCompiler := "/some/default/compiler"
	binDir := "/some/dir/"
	tags := make(map[string]bool)

	// No tags case.
	actual := linuxClangPath(tags, binDir, defaultCompiler)
	expected := binDir + "llvm-9.0.1/bin/clang"
	assert.Equal(t, actual, expected, "unexpected clang path")

	// Recent tag case.
	tags["v5.9"] = true
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
