// Copyright 2019 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package bisect

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"os"
	"strconv"
	"testing"

	"github.com/google/syzkaller/pkg/instance"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/pkg/vcs"
)

// testEnv will implement instance.BuilderTester. This allows us to
// set bisect.env.inst to a testEnv object.
type testEnv struct {
	repo *vcs.TestRepo
	r    vcs.Repo
	t    *testing.T
	// TODO: add a "fix bool" here so that Test() can return results according to
	// whether fix/cause bisection is happening.
}

func (env *testEnv) BuildSyzkaller(repo, commit string) error {
	return nil
}

func (env *testEnv) BuildKernel(compilerBin, userspaceDir, cmdlineFile, sysctlFile string,
	kernelConfig []byte) (string, error) {
	return "", nil
}

func (env *testEnv) Test(numVMs int, reproSyz, reproOpts, reproC []byte) ([]error, error) {
	hc, err := env.r.HeadCommit()
	if err != nil {
		env.t.Fatal(err)
	}
	// For cause bisection, if newer than or equal to 602, it crashes.
	// -- 602 is the cause commit.
	// TODO: for fix bisection(check env.fix), if older than 602, it crashes.
	// -- 602 is the fix commit.
	val, err := strconv.Atoi(hc.Title)
	if err != nil {
		env.t.Fatalf("invalid commit title: %v", val)
	}
	if val >= 602 {
		var errors []error
		for i := 0; i < numVMs; i++ {
			errors = append(errors, &instance.CrashError{
				Report: &report.Report{
					Title: fmt.Sprintf("crashes at %v", hc.Title),
				},
			})
		}
		return errors, nil
	}
	var errors []error
	for i := 0; i < numVMs; i++ {
		errors = append(errors, nil)
	}
	return errors, nil
}

// TestBisectCause tests that bisection returns the correct cause
// commit.
func TestBisectCause(t *testing.T) {
	t.Parallel()
	baseDir, err := ioutil.TempDir("", "syz-git-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(baseDir)
	originRepo := vcs.CreateTestRepo(t, baseDir, "originRepo")
	for rv := 4; rv < 10; rv++ {
		for i := 0; i < 6; i++ {
			originRepo.CommitChange(fmt.Sprintf("%v", rv*100+i))
			if i == 0 {
				originRepo.SetTag(fmt.Sprintf("v%v.0", rv))
			}
		}
	}
	if !originRepo.SupportsBisection() {
		t.Skip("bisection is unsupported by git (probably too old version)")
	}
	repo := vcs.CloneTestRepo(t, baseDir, "repo", originRepo)
	r, err := vcs.NewRepo("test", "64", repo.Dir)
	if err != nil {
		t.Fatal(err)
	}
	head, err := r.HeadCommit()
	if err != nil {
		t.Fatal(err)
	}
	cfg := &Config{
		Fix:   false,
		Trace: new(bytes.Buffer),
		Manager: mgrconfig.Config{
			TargetOS:     "test",
			TargetVMArch: "64",
			Type:         "qemu",
			KernelSrc:    repo.Dir,
		},
		Kernel: KernelConfig{
			Commit: head.Hash,
			Repo:   originRepo.Dir,
		},
	}
	inst := &testEnv{
		repo: repo,
		r:    r,
		t:    t,
	}
	commits, rep, err := runImpl(cfg, r, r.(vcs.Bisecter), inst)
	if err != nil {
		t.Fatalf("returned error: '%v'", err)
	}
	if len(commits) != 1 {
		t.Fatalf("Got %d commits: %v", len(commits), commits)
	}
	if commits[0].Title != "602" {
		t.Fatalf("Expected commit '602' got '%v'", commits[0].Title)
	}
	if rep == nil {
		t.Fatal("returned rep==nil, report should not be empty")
	}
}
