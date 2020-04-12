// Copyright 2019 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vcs

import (
	"bytes"
	"io/ioutil"
	"os"
	"strings"
	"testing"

	"github.com/google/syzkaller/pkg/osutil"
)

type MinimizationTest struct {
	config         string
	baselineConfig string
	// Output contains expected config option
	expectedConfig string
	// Minimization is expected to pass or fail
	passing bool
}

func createTestLinuxRepo(t *testing.T) string {
	baseDir, err := ioutil.TempDir("", "syz-config-bisect-test")
	if err != nil {
		t.Fatal(err)
	}
	repo := CreateTestRepo(t, baseDir, "")
	repo.CommitChange("commit")
	repo.SetTag("v4.1")
	err = os.MkdirAll(baseDir+"/tools/testing/ktest", 0755)
	if err != nil {
		t.Fatal(err)
	}
	err = os.MkdirAll(baseDir+"/scripts/kconfig", 0755)
	if err != nil {
		t.Fatal(err)
	}

	// Copy stubbed scripts used by config bisect
	err = osutil.CopyFile("testdata/linux/config-bisect.pl",
		baseDir+"/tools/testing/ktest/config-bisect.pl")
	if err != nil {
		t.Fatal(err)
	}
	err = osutil.CopyFile("testdata/linux/merge_config.sh",
		baseDir+"/scripts/kconfig/merge_config.sh")
	if err != nil {
		t.Fatal(err)
	}

	return baseDir
}

func TestMinimizationResults(t *testing.T) {
	tests := []MinimizationTest{
		{
			config:         "CONFIG_ORIGINAL=y",
			baselineConfig: "CONFIG_FAILING=y",
			expectedConfig: "CONFIG_ORIGINAL=y",
			passing:        false,
		},
		{
			config:         "CONFIG_ORIGINAL=y",
			baselineConfig: "CONFIG_REPRODUCES_CRASH=y",
			expectedConfig: "CONFIG_REPRODUCES_CRASH=y",
			passing:        true,
		},
		{
			config:         "CONFIG_ORIGINAL=y",
			baselineConfig: "CONFIG_NOT_REPRODUCE_CRASH=y",
			expectedConfig: "CONFIG_ORIGINAL=y",
			passing:        true,
		},
		{
			config:         configBisectTag,
			baselineConfig: "CONFIG_NOT_REPRODUCE_CRASH=y",
			expectedConfig: configBisectTag,
			passing:        true,
		},
	}

	trace := new(bytes.Buffer)
	baseDir := createTestLinuxRepo(t)
	repo, err := NewRepo("linux", "64", baseDir)
	if err != nil {
		t.Fatalf("Unable to create repository")
	}
	pred := func(test []byte) (BisectResult, error) {
		if strings.Contains(string(test), "CONFIG_REPRODUCES_CRASH=y") {
			return BisectBad, nil
		}
		return BisectGood, nil
	}

	minimizer, ok := repo.(ConfigMinimizer)
	if !ok {
		t.Fatalf("Config minimization is not implemented")
	}
	for _, test := range tests {
		outConfig, err := minimizer.Minimize([]byte(test.config),
			[]byte(test.baselineConfig), trace, pred)
		if test.passing && err != nil {
			t.Fatalf("Failed to run Minimize")
		} else if test.passing && !strings.Contains(string(outConfig),
			test.expectedConfig) {
			t.Fatalf("Output is not expected %v vs. %v", string(outConfig),
				test.expectedConfig)
		}
	}
	t.Log(trace.String())
}
