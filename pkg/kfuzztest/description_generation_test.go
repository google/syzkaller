// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
package kfuzztest

import (
	"fmt"
	"os"
	"path"
	"runtime"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/sys/targets"
	"github.com/stretchr/testify/require"
)

type testData struct {
	dir  string
	desc string
}

func TestBuildDescriptions(t *testing.T) {
	testCases, err := readTestCases("./testdata")
	require.NoError(t, err)

	target := targets.Get(targets.Linux, targets.AMD64)
	if runtime.GOOS != target.BuildOS {
		t.Skip("we cannot build Linux on this target")
	}
	if target.BrokenCompiler != "" {
		t.Skip("skipping the test due to broken cross-compiler:\n" + target.BrokenCompiler)
	}
	for _, tc := range testCases {
		t.Run(tc.dir, func(t *testing.T) {
			runTest(t, target, tc)
		})
	}
}

// Tests that the description inferred from a compiled binary matches an
// expected description.
func runTest(t *testing.T, target *targets.Target, tc testData) {
	// Compile the C binary containing the metadata.
	cmd := flags(tc.dir)
	out, err := osutil.RunCmd(time.Hour, "", target.CCompiler, cmd...)
	require.NoErrorf(t, err, "Failed to compile: %s", string(out))
	// Cleanup the compiled binary.
	defer func() {
		out, err := osutil.RunCmd(time.Hour, "", "rm", path.Join(tc.dir, "bin"))
		if err != nil {
			require.NoErrorf(t, err, "Failed to cleanup: %s", string(out))
		}
	}()

	binaryPath := path.Join(tc.dir, "bin")
	desc, err := ExtractDescription(binaryPath)
	require.NoError(t, err)

	if diffDesc := cmp.Diff(tc.desc, desc); diffDesc != "" {
		fmt.Print(diffDesc)
		t.Fail()
		return
	}
}

func flags(testDir string) []string {
	return []string{
		"-g",
		"-T",
		path.Join(testDir, "..", "linker.ld"),
		"-o",
		path.Join(testDir, "bin"),
		path.Join(testDir, "prog.c"),
	}
}

func readTestCases(dir string) ([]testData, error) {
	var testCases []testData
	testDirs, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	for _, subDir := range testDirs {
		if !subDir.IsDir() {
			continue
		}
		testData, err := readTestdata(path.Join(dir, subDir.Name()))
		if err != nil {
			return nil, err
		}
		testCases = append(testCases, testData)
	}

	return testCases, nil
}

func readTestdata(testDir string) (testData, error) {
	content, err := os.ReadFile(path.Join(testDir, "desc.txt"))
	if err != nil {
		return testData{}, err
	}

	return testData{
		dir:  testDir,
		desc: string(content),
	}, nil
}
