// Copyright 2019 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package bisect

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"math"
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
	repo        *vcs.TestRepo
	r           vcs.Repo
	t           *testing.T
	fix         bool
	brokenStart float64
	brokenEnd   float64
	culprit     float64
}

func (env *testEnv) BuildSyzkaller(repo, commit string) error {
	return nil
}

func (env *testEnv) BuildKernel(compilerBin, userspaceDir, cmdlineFile, sysctlFile string,
	kernelConfig []byte) (string, error) {
	return "", nil
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

func nilErrors(num int) []error {
	var errors []error
	for i := 0; i < num; i++ {
		errors = append(errors, nil)
	}
	return errors
}

func (env *testEnv) Test(numVMs int, reproSyz, reproOpts, reproC []byte) ([]error, error) {
	hc, err := env.r.HeadCommit()
	if err != nil {
		env.t.Fatal(err)
	}
	commit, err := strconv.ParseFloat(hc.Title, 64)
	if err != nil {
		env.t.Fatalf("invalid commit title: %v", hc.Title)
	}
	var e error
	var res []error
	if commit >= env.brokenStart && commit <= env.brokenEnd {
		e = fmt.Errorf("broken build")
	} else if commit < env.culprit && !env.fix || commit >= env.culprit && env.fix {
		res = nilErrors(numVMs)
	} else {
		res = crashErrors(numVMs, "crash occurs")
	}
	return res, e
}

type Ctx struct {
	t          *testing.T
	baseDir    string
	repo       *vcs.TestRepo
	r          vcs.Repo
	cfg        *Config
	inst       *testEnv
	originRepo *vcs.TestRepo
}

func NewCtx(t *testing.T, fix bool, brokenStart, brokenEnd, culprit float64, commit string) *Ctx {
	baseDir, err := ioutil.TempDir("", "syz-git-test")
	if err != nil {
		t.Fatal(err)
	}
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
	sc, err := r.GetCommitByTitle(commit)
	if err != nil {
		t.Fatal(err)
	}
	cfg := &Config{
		Fix:   fix,
		Trace: new(bytes.Buffer),
		Manager: mgrconfig.Config{
			TargetOS:     "test",
			TargetVMArch: "64",
			Type:         "qemu",
			KernelSrc:    repo.Dir,
		},
		Kernel: KernelConfig{
			Repo:   originRepo.Dir,
			Commit: sc.Hash,
		},
	}
	inst := &testEnv{
		repo:        repo,
		r:           r,
		t:           t,
		fix:         fix,
		brokenStart: brokenStart,
		brokenEnd:   brokenEnd,
		culprit:     culprit,
	}
	c := &Ctx{
		t:          t,
		baseDir:    baseDir,
		repo:       repo,
		r:          r,
		cfg:        cfg,
		inst:       inst,
		originRepo: originRepo,
	}
	return c
}

type BisectionTests struct {
	// input environment
	name        string
	fix         bool
	startCommit string
	brokenStart float64
	brokenEnd   float64
	// expected output
	errIsNil  bool
	commitLen int
	repIsNil  bool
	// input and output
	culprit float64
}

func TestBisectionResults(t *testing.T) {
	t.Parallel()
	var tests = []BisectionTests{
		// Tests that bisection returns the correct cause commit.
		{
			name:        "bisect cause finds cause",
			fix:         false,
			startCommit: "905",
			brokenStart: math.Inf(0),
			brokenEnd:   0,
			errIsNil:    true,
			commitLen:   1,
			repIsNil:    false,
			culprit:     602,
		},
		// Tests that cause bisection returns error when crash does not reproduce
		// on the original commit.
		{
			name:        "bisect cause does not repro",
			fix:         false,
			startCommit: "400",
			brokenStart: math.Inf(0),
			brokenEnd:   0,
			errIsNil:    false,
			commitLen:   0,
			repIsNil:    true,
			culprit:     math.Inf(0),
		},
		// Tests that no commits are returned when crash occurs on oldest commit
		// for cause bisection.
		{
			name:        "bisect cause crashes oldest",
			fix:         false,
			startCommit: "905",
			brokenStart: math.Inf(0),
			brokenEnd:   0,
			errIsNil:    true,
			commitLen:   0,
			repIsNil:    false,
			culprit:     0,
		},
		// Tests that more than 1 commit is returned when cause bisection is
		// inconclusive.
		{
			name:        "bisect cause inconclusive",
			fix:         false,
			startCommit: "802",
			brokenStart: 500,
			brokenEnd:   700,
			errIsNil:    true,
			commitLen:   14,
			repIsNil:    true,
			culprit:     605,
		},
		// Tests that bisection returns the correct fix commit.
		{
			name:        "bisect fix finds fix",
			fix:         true,
			startCommit: "400",
			brokenStart: math.Inf(0),
			brokenEnd:   0,
			errIsNil:    true,
			commitLen:   1,
			repIsNil:    true,
			culprit:     500,
		},
		// Tests that fix bisection returns error when crash does not reproduce
		// on the original commit.
		{
			name:        "bisect fix does not repro",
			fix:         true,
			startCommit: "905",
			brokenStart: math.Inf(0),
			brokenEnd:   0,
			errIsNil:    false,
			commitLen:   0,
			repIsNil:    true,
			culprit:     0,
		},
		// Tests that no commits are returned when crash occurs on HEAD
		// for fix bisection.
		{
			name:        "bisect fix crashes HEAD",
			fix:         true,
			startCommit: "400",
			brokenStart: math.Inf(0),
			brokenEnd:   0,
			errIsNil:    true,
			commitLen:   0,
			repIsNil:    false,
			culprit:     1000,
		},
		// Tests that more than 1 commit is returned when fix bisection is
		// inconclusive.
		{
			name:        "bisect fix inconclusive",
			fix:         true,
			startCommit: "400",
			brokenStart: 500,
			brokenEnd:   600,
			errIsNil:    true,
			commitLen:   8,
			repIsNil:    true,
			culprit:     501,
		},
	}
	for _, test := range tests {
		t.Run(fmt.Sprintf("%v", test.name), func(t *testing.T) {
			c := NewCtx(t, test.fix, test.brokenStart, test.brokenEnd, test.culprit, test.startCommit)
			defer os.RemoveAll(c.baseDir)
			commits, rep, err := runImpl(c.cfg, c.r, c.r.(vcs.Bisecter), c.inst)
			if test.errIsNil && err != nil || !test.errIsNil && err == nil {
				t.Fatalf("returned error: '%v'", err)
			}
			if len(commits) != test.commitLen {
				t.Fatalf("expected %d commits got %d commits", test.commitLen, len(commits))
			}
			expectedTitle := fmt.Sprintf("%v", test.culprit)
			if len(commits) == 1 && expectedTitle != commits[0].Title {
				t.Fatalf("expected commit '%v' got '%v'", expectedTitle, commits[0].Title)
			}
			if test.repIsNil && rep != nil || !test.repIsNil && rep == nil {
				t.Fatalf("returned rep: '%v'", err)
			}
		})
	}
}
