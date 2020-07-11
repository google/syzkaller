// Copyright 2019 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vcs

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/google/syzkaller/pkg/osutil"
)

type MinimizationTest struct {
	config         string
	baselineConfig string
	// Output contains expected config option.
	expectedConfig string
	// Minimization is expected to pass or fail.
	passing bool
}

func TestConfigMinimizer(t *testing.T) {
	if runtime.GOOS != "linux" {
		// The test config-bisect.pl uses bash-isms and can't run on OS that don't have bash.
		t.Skipf("skipping on non-linux")
	}
	t.Parallel()
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
			config:         configBisectTag,
			baselineConfig: "CONFIG_NOT_REPRODUCE_CRASH=y",
			expectedConfig: configBisectTag,
			passing:        true,
		},
	}

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
	for i, test := range tests {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			trace := new(bytes.Buffer)
			outConfig, err := minimizer.Minimize([]byte(test.config),
				[]byte(test.baselineConfig), trace, pred)
			t.Log(trace.String())
			if test.passing && err != nil {
				t.Fatalf("failed to run Minimize: %v", err)
			} else if test.passing && !strings.Contains(string(outConfig),
				test.expectedConfig) {
				t.Fatalf("output is not expected %v vs. %v", string(outConfig),
					test.expectedConfig)
			}
		})
	}
}

func createTestLinuxRepo(t *testing.T) string {
	baseDir, err := ioutil.TempDir("", "syz-config-bisect-test")
	if err != nil {
		t.Fatal(err)
	}
	repo := CreateTestRepo(t, baseDir, "")
	if !repo.SupportsBisection() {
		t.Skip("bisection is unsupported by git (probably too old version)")
	}
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

	// Copy stubbed scripts used by config bisect.
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
