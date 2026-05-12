// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package build

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/sys/targets"
	"github.com/stretchr/testify/require"
)

func TestShellBuild(t *testing.T) {
	kernelDir := t.TempDir()
	outputDir := t.TempDir()

	script := filepath.Join(kernelDir, "build.sh")
	err := osutil.WriteExecFile(script, []byte(`#!/bin/sh
echo $SYZ_BUILD_ACTION > action
mkdir -p $SYZ_OUTPUT_DIR/obj
touch $SYZ_OUTPUT_DIR/image
cp $SYZ_LINKER $SYZ_OUTPUT_DIR/obj/vmlinux
`))
	require.NoError(t, err)

	params := Params{
		TargetOS:   targets.Linux,
		TargetArch: targets.AMD64,
		KernelDir:  kernelDir,
		OutputDir:  outputDir,
		Linker:     osutil.Abs(os.Args[0]),
		Make:       "SHELL: " + script,
	}

	_, err = Image(params)
	require.NoError(t, err)

	action, err := os.ReadFile(filepath.Join(kernelDir, "action"))
	require.NoError(t, err)
	require.Equal(t, "build\n", string(action))

	require.True(t, osutil.IsExist(filepath.Join(outputDir, "image")))
	require.True(t, osutil.IsExist(filepath.Join(outputDir, "obj", "vmlinux")))

	err = Clean(params)
	require.NoError(t, err)

	action, err = os.ReadFile(filepath.Join(kernelDir, "action"))
	require.NoError(t, err)
	require.Equal(t, "clean\n", string(action))
}

func TestShellBuildFail(t *testing.T) {
	kernelDir := t.TempDir()
	outputDir := t.TempDir()

	params := Params{
		TargetOS:   targets.Linux,
		TargetArch: targets.AMD64,
		KernelDir:  kernelDir,
		OutputDir:  outputDir,
		Make:       "SHELL: exit 1",
	}

	_, err := Image(params)
	require.Error(t, err)
}

func TestShellBuildMissingFile(t *testing.T) {
	kernelDir := t.TempDir()
	outputDir := t.TempDir()

	params := Params{
		TargetOS:   targets.Linux,
		TargetArch: targets.AMD64,
		KernelDir:  kernelDir,
		OutputDir:  outputDir,
		Make:       "SHELL: touch $SYZ_OUTPUT_DIR/image", // missing obj/vmlinux
	}

	_, err := Image(params)
	require.ErrorContains(t, err, "build did not produce required file obj/vmlinux")
}
