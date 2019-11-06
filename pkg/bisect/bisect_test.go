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
	t    *testing.T
	r    vcs.Repo
	test BisectionTest
}

func (env *testEnv) BuildSyzkaller(repo, commit string) error {
	return nil
}

func (env *testEnv) BuildKernel(compilerBin, userspaceDir, cmdlineFile, sysctlFile string,
	kernelConfig []byte) (string, string, error) {
	commit := env.headCommit()
	kernelSign := fmt.Sprintf("sign-%v", commit)
	if commit >= env.test.sameBinaryStart && commit <= env.test.sameBinaryEnd {
		kernelSign = "same-sign"
	}
	return "", kernelSign, nil
}

func (env *testEnv) Test(numVMs int, reproSyz, reproOpts, reproC []byte) ([]error, error) {
	commit := env.headCommit()
	if commit >= env.test.brokenStart && commit <= env.test.brokenEnd {
		return nil, fmt.Errorf("broken build")
	}
	if !env.test.fix && commit >= env.test.culprit || env.test.fix && commit < env.test.culprit {
		return crashErrors(numVMs, "crash occurs"), nil
	}
	return make([]error, numVMs), nil
}

func (env *testEnv) headCommit() int {
	com, err := env.r.HeadCommit()
	if err != nil {
		env.t.Fatal(err)
	}
	commit, err := strconv.ParseUint(com.Title, 10, 64)
	if err != nil {
		env.t.Fatalf("invalid commit title: %v", com.Title)
	}
	return int(commit)
}

func runBisection(t *testing.T, test BisectionTest) (*Result, error) {
	baseDir, err := ioutil.TempDir("", "syz-bisect-test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(baseDir)
	repo := vcs.CreateTestRepo(t, baseDir, "repo")
	if !repo.SupportsBisection() {
		t.Skip("bisection is unsupported by git (probably too old version)")
	}
	for rv := 4; rv < 10; rv++ {
		for i := 0; i < 6; i++ {
			repo.CommitChange(fmt.Sprintf("%v", rv*100+i))
			if i == 0 {
				repo.SetTag(fmt.Sprintf("v%v.0", rv))
			}
		}
	}
	r, err := vcs.NewRepo("test", "64", repo.Dir)
	if err != nil {
		t.Fatal(err)
	}
	sc, err := r.GetCommitByTitle(fmt.Sprint(test.startCommit))
	if err != nil {
		t.Fatal(err)
	}
	trace := new(bytes.Buffer)
	cfg := &Config{
		Fix:   test.fix,
		Trace: trace,
		Manager: mgrconfig.Config{
			TargetOS:     "test",
			TargetVMArch: "64",
			Type:         "qemu",
			KernelSrc:    repo.Dir,
		},
		Kernel: KernelConfig{
			Repo:   repo.Dir,
			Commit: sc.Hash,
		},
	}
	inst := &testEnv{
		t:    t,
		r:    r,
		test: test,
	}
	res, err := runImpl(cfg, r, r.(vcs.Bisecter), inst)
	t.Log(trace.String())
	return res, err
}

type BisectionTest struct {
	// input environment
	name        string
	fix         bool
	startCommit int
	brokenStart int
	brokenEnd   int
	// Range of commits that result in the same kernel binary signature.
	sameBinaryStart int
	sameBinaryEnd   int
	// expected output
	expectErr    bool
	expectRep    bool
	noopChange   bool
	commitLen    int
	oldestLatest int
	// input and output
	culprit int
}

func TestBisectionResults(t *testing.T) {
	t.Parallel()
	tests := []BisectionTest{
		// Tests that bisection returns the correct cause commit.
		{
			name:        "cause-finds-cause",
			startCommit: 905,
			commitLen:   1,
			expectRep:   true,
			culprit:     602,
		},
		// Tests that cause bisection returns error when crash does not reproduce
		// on the original commit.
		{
			name:        "cause-does-not-repro",
			startCommit: 400,
			expectErr:   true,
		},
		// Tests that no commits are returned when crash occurs on oldest commit
		// for cause bisection.
		{
			name:         "cause-crashes-oldest",
			startCommit:  905,
			commitLen:    0,
			expectRep:    true,
			culprit:      0,
			oldestLatest: 400,
		},
		// Tests that more than 1 commit is returned when cause bisection is inconclusive.
		{
			name:        "cause-inconclusive",
			startCommit: 802,
			brokenStart: 500,
			brokenEnd:   700,
			commitLen:   14,
			culprit:     605,
		},
		// Tests that bisection returns the correct fix commit.
		{
			name:        "fix-finds-fix",
			fix:         true,
			startCommit: 400,
			commitLen:   1,
			culprit:     500,
		},
		// Tests that fix bisection returns error when crash does not reproduce
		// on the original commit.
		{
			name:        "fix-does-not-repro",
			fix:         true,
			startCommit: 905,
			expectErr:   true,
		},
		// Tests that no commits are returned when crash occurs on HEAD
		// for fix bisection.
		{
			name:         "fix-crashes-HEAD",
			fix:          true,
			startCommit:  400,
			commitLen:    0,
			expectRep:    true,
			culprit:      1000,
			oldestLatest: 905,
		},
		// Tests that more than 1 commit is returned when fix bisection is inconclusive.
		{
			name:        "fix-inconclusive",
			fix:         true,
			startCommit: 400,
			brokenStart: 500,
			brokenEnd:   600,
			commitLen:   8,
			culprit:     501,
		},
		{
			name:            "cause-same-binary",
			startCommit:     905,
			commitLen:       1,
			expectRep:       true,
			culprit:         503,
			sameBinaryStart: 502,
			sameBinaryEnd:   503,
			noopChange:      true,
		},
		{
			name:            "cause-same-binary-off-by-one",
			startCommit:     905,
			commitLen:       1,
			expectRep:       true,
			culprit:         503,
			sameBinaryStart: 400,
			sameBinaryEnd:   502,
		},
		{
			name:            "cause-same-binary-off-by-one-2",
			startCommit:     905,
			commitLen:       1,
			expectRep:       true,
			culprit:         503,
			sameBinaryStart: 503,
			sameBinaryEnd:   905,
		},
		{
			name:            "fix-same-binary",
			fix:             true,
			startCommit:     400,
			commitLen:       1,
			culprit:         503,
			sameBinaryStart: 502,
			sameBinaryEnd:   504,
			noopChange:      true,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			if test.expectErr &&
				(test.commitLen != 0 ||
					test.expectRep ||
					test.oldestLatest != 0 ||
					test.culprit != 0) {
				t.Fatalf("expecting non-default values on error")
			}
			if test.brokenStart > test.brokenEnd {
				t.Fatalf("bad broken start/end: %v/%v",
					test.brokenStart, test.brokenEnd)
			}
			if test.sameBinaryStart > test.sameBinaryEnd {
				t.Fatalf("bad same binary start/end: %v/%v",
					test.sameBinaryStart, test.sameBinaryEnd)
			}
			res, err := runBisection(t, test)
			if test.expectErr != (err != nil) {
				t.Fatalf("returned error: %v", err)
			}
			if err != nil {
				if res != nil {
					t.Fatalf("got both result and error: '%v' %+v", err, *res)
				}
				return
			}
			if len(res.Commits) != test.commitLen {
				t.Fatalf("expected %d commits got %d commits", test.commitLen, len(res.Commits))
			}
			expectedTitle := fmt.Sprint(test.culprit)
			if len(res.Commits) == 1 && expectedTitle != res.Commits[0].Title {
				t.Fatalf("expected commit '%v' got '%v'", expectedTitle, res.Commits[0].Title)
			}
			if test.expectRep != (res.Report != nil) {
				t.Fatalf("got rep: %v, want: %v", res.Report, test.expectRep)
			}
			if res.NoopChange != test.noopChange {
				t.Fatalf("got noop change: %v, want: %v", res.NoopChange, test.noopChange)
			}
			if test.oldestLatest != 0 && fmt.Sprint(test.oldestLatest) != res.Commit.Title ||
				test.oldestLatest == 0 && res.Commit != nil {
				t.Fatalf("expected latest/oldest: %v got '%v'",
					test.oldestLatest, res.Commit.Title)
			}
		})
	}
}

func crashErrors(num int, title string) []error {
	var errors []error
	for i := 0; i < num; i++ {
		errors = append(errors, &instance.CrashError{
			Report: &report.Report{
				Title: fmt.Sprintf("crashes at %v", title),
			},
		})
	}
	return errors
}
