// Copyright 2019 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package bisect

import (
	"errors"
	"fmt"
	"strconv"
	"testing"

	"github.com/google/syzkaller/pkg/build"
	"github.com/google/syzkaller/pkg/debugtracer"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/instance"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/pkg/report/crash"
	"github.com/google/syzkaller/pkg/vcs"
	"github.com/google/syzkaller/sys/targets"
	"github.com/stretchr/testify/assert"
)

// testEnv will implement instance.BuilderTester. This allows us to
// set bisect.env.inst to a testEnv object.
type testEnv struct {
	t *testing.T
	r vcs.Repo
	// Kernel config used in "build"
	config string
	test   BisectionTest
}

func (env *testEnv) BuildSyzkaller(repo, commit string) (string, error) {
	return "", nil
}

func (env *testEnv) CleanKernel(buildCfg *instance.BuildKernelConfig) error {
	return nil
}

func (env *testEnv) EnableMemoryDumps(folder string) {
}

func (env *testEnv) BuildKernel(buildCfg *instance.BuildKernelConfig) (string, build.ImageDetails, error) {
	commit := env.headCommit()
	configHash := hash.String(buildCfg.KernelConfig)
	details := build.ImageDetails{}
	details.Signature = fmt.Sprintf("%v-%v", commit, configHash)
	if commit >= env.test.sameBinaryStart && commit <= env.test.sameBinaryEnd {
		details.Signature = "same-sign-" + configHash
	}
	env.config = string(buildCfg.KernelConfig)
	if env.config == "baseline-fails" {
		return "", details, fmt.Errorf("failure")
	}
	return "", details, nil
}

func (env *testEnv) Test(numVMs int, reproSyz, reproOpts, reproC []byte) ([]instance.EnvTestResult, error) {
	commit := env.headCommit()
	if commit >= env.test.brokenStart && commit <= env.test.brokenEnd ||
		env.config == "baseline-skip" {
		var ret []instance.EnvTestResult
		for i := 0; i < numVMs; i++ {
			ret = append(ret, instance.EnvTestResult{
				Error: &instance.TestError{
					Boot:  true,
					Title: "kernel doesn't boot",
				},
			})
		}
		return ret, nil
	}
	if commit >= env.test.infraErrStart && commit <= env.test.infraErrEnd {
		var ret []instance.EnvTestResult
		for i := 0; i < numVMs; i++ {
			var err error
			// More than 50% failures.
			if i*2 <= numVMs {
				err = &instance.TestError{
					Infra: true,
					Title: "failed to create a VM",
				}
			}
			ret = append(ret, instance.EnvTestResult{
				Error: err,
			})
		}
		return ret, nil
	}
	var ret []instance.EnvTestResult

	fixed := false
	if env.test.fixCommit != "" {
		commit, err := env.r.GetCommitByTitle(env.test.fixCommit)
		if err != nil {
			return ret, err
		}
		fixed = commit != nil
	}

	introduced := true
	if env.test.introduced != "" {
		commit, err := env.r.GetCommitByTitle(env.test.introduced)
		if err != nil {
			return ret, err
		}
		introduced = commit != nil
	}

	if (env.config == "baseline-repro" || env.config == "new-minimized-config" || env.config == "original config") &&
		introduced && !fixed {
		if env.test.flaky {
			crashed := max(2, numVMs/6)
			ret = crashErrors(crashed, numVMs-crashed, "crash occurs", env.test.reportType)
		} else {
			ret = crashErrors(numVMs, 0, "crash occurs", env.test.reportType)
		}
		return ret, nil
	}
	ret = make([]instance.EnvTestResult, numVMs)
	if env.test.injectSyzFailure {
		ret[0] = instance.EnvTestResult{
			Error: &instance.CrashError{
				Report: &report.Report{
					Title: "SYZFATAL: test",
					Type:  crash.SyzFailure,
				},
			},
		}
	} else if env.test.injectLostConnection {
		for i := 0; i < numVMs/3; i++ {
			ret[i] = instance.EnvTestResult{
				Error: &instance.CrashError{
					Report: &report.Report{
						Title: "lost connection to test machine",
						Type:  crash.LostConnection,
					},
				},
			}
		}
	}
	return ret, nil
}

func (env *testEnv) headCommit() int {
	com, err := env.r.Commit(vcs.HEAD)
	if err != nil {
		env.t.Fatal(err)
	}
	commit, err := strconv.ParseUint(com.Title, 10, 64)
	if err != nil {
		env.t.Fatalf("invalid commit title: %v", com.Title)
	}
	return int(commit)
}

func createTestRepo(t *testing.T) string {
	baseDir := t.TempDir()
	repo := vcs.CreateTestRepo(t, baseDir, "")
	if !repo.SupportsBisection() {
		t.Skip("bisection is unsupported by git (probably too old version)")
	}
	for rv := 4; rv < 10; rv++ {
		for i := 0; i < 6; i++ {
			if rv == 7 && i == 0 {
				// Create a slightly special commit graph here (for #1527):
				// Commit 650 is part of 700 release, but it does not have
				// 600 (the previous release) in parents, instead it's based
				// on the previous-previous release 500.
				repo.Git("checkout", "v5.0")
				com := repo.CommitChange("650")
				repo.Git("checkout", "master")
				repo.Git("merge", "-m", "700", com.Hash)
			} else if rv == 8 && i == 4 {
				// Let's construct a more elaborate case. See #4117.
				// We branch off at 700 and merge it into 804.
				repo.Git("checkout", "v7.0")
				repo.CommitChange("790")
				repo.CommitChange("791")
				com := repo.CommitChange("792")
				repo.Git("checkout", "master")
				repo.Git("merge", "-m", "804", com.Hash)
			} else {
				repo.CommitChange(fmt.Sprintf("%v", rv*100+i))
			}
			if i == 0 {
				repo.SetTag(fmt.Sprintf("v%v.0", rv))
			}
		}
	}
	// Emulate another tree, that's needed for cross-tree tests and
	// for cause bisections for commits not reachable from master.
	repo.Git("checkout", "v8.0")
	repo.Git("checkout", "-b", "v8-branch")
	repo.CommitFileChange("850", "v8-branch")
	repo.CommitChange("851")
	repo.CommitChange("852")
	return baseDir
}

func testBisection(t *testing.T, baseDir string, test BisectionTest) {
	r, err := vcs.NewRepo(targets.TestOS, targets.TestArch64, baseDir, vcs.OptPrecious)
	if err != nil {
		t.Fatal(err)
	}
	if test.startCommitBranch != "" {
		r.SwitchCommit(test.startCommitBranch)
	} else {
		r.SwitchCommit("master")
	}
	sc, err := r.GetCommitByTitle(fmt.Sprint(test.startCommit))
	if err != nil {
		t.Fatal(err)
	}
	if sc == nil {
		t.Fatalf("start commit %v is not found", test.startCommit)
	}
	r.SwitchCommit("master")
	cfg := &Config{
		Fix:   test.fix,
		Trace: &debugtracer.TestTracer{T: t},
		Manager: &mgrconfig.Config{
			Derived: mgrconfig.Derived{
				TargetOS:     targets.TestOS,
				TargetVMArch: targets.TestArch64,
			},
			Type:      "qemu",
			KernelSrc: baseDir,
		},
		Kernel: KernelConfig{
			Repo:           baseDir,
			Branch:         "master",
			Commit:         sc.Hash,
			CommitTitle:    sc.Title,
			Config:         []byte("original config"),
			BaselineConfig: []byte(test.baselineConfig),
		},
		CrossTree: test.crossTree,
	}
	inst := &testEnv{
		t:    t,
		r:    r,
		test: test,
	}

	checkBisectionError := func(test BisectionTest, res *Result, err error) {
		if test.expectErr != (err != nil) {
			t.Fatalf("expected error %v, got %v", test.expectErr, err)
		}
		if test.expectErrType != nil && !errors.As(err, &test.expectErrType) {
			t.Fatalf("expected %#v error, got %#v", test.expectErrType, err)
		}
		if err != nil {
			if res != nil {
				t.Fatalf("got both result and error: '%v' %+v", err, *res)
			}
		} else {
			checkBisectionResult(t, test, res)
		}
		if test.extraTest != nil {
			test.extraTest(t, res)
		}
	}

	res, err := runImpl(cfg, r, inst)
	checkBisectionError(test, res, err)
	if !test.crossTree && !test.noFakeHashTest {
		// Should be mitigated via GetCommitByTitle during bisection.
		cfg.Kernel.Commit = fmt.Sprintf("fake-hash-for-%v-%v", cfg.Kernel.Commit, cfg.Kernel.CommitTitle)
		res, err = runImpl(cfg, r, inst)
		checkBisectionError(test, res, err)
	}
}

func checkBisectionResult(t *testing.T, test BisectionTest, res *Result) {
	if len(res.Commits) != test.commitLen {
		t.Fatalf("expected %d commits got %d commits", test.commitLen, len(res.Commits))
	}
	expectedTitle := test.introduced
	if test.fix {
		expectedTitle = test.fixCommit
	}
	if len(res.Commits) == 1 && expectedTitle != res.Commits[0].Title {
		t.Fatalf("expected commit '%v' got '%v'", expectedTitle, res.Commits[0].Title)
	}
	if test.expectRep != (res.Report != nil) {
		t.Fatalf("got rep: %v, want: %v", res.Report, test.expectRep)
	}
	if res.NoopChange != test.noopChange {
		t.Fatalf("got noop change: %v, want: %v", res.NoopChange, test.noopChange)
	}
	if res.IsRelease != test.isRelease {
		t.Fatalf("got release change: %v, want: %v", res.IsRelease, test.isRelease)
	}
	if test.oldestLatest != 0 && fmt.Sprint(test.oldestLatest) != res.Commit.Title ||
		test.oldestLatest == 0 && res.Commit != nil {
		t.Fatalf("expected latest/oldest: %v got '%v'",
			test.oldestLatest, res.Commit.Title)
	}
	if test.resultingConfig != "" && test.resultingConfig != string(res.Config) {
		t.Fatalf("expected resulting config: %q got %q",
			test.resultingConfig, res.Config)
	}
}

type BisectionTest struct {
	// input environment
	name string
	fix  bool
	// By default it's set to "master".
	startCommitBranch string
	startCommit       int
	brokenStart       int
	brokenEnd         int
	infraErrStart     int
	infraErrEnd       int
	reportType        crash.Type
	// Range of commits that result in the same kernel binary signature.
	sameBinaryStart int
	sameBinaryEnd   int
	// expected output
	expectErr     bool
	expectErrType any
	// Expect res.Report != nil.
	expectRep            bool
	noopChange           bool
	isRelease            bool
	flaky                bool
	injectSyzFailure     bool
	injectLostConnection bool
	// Expected number of returned commits for inconclusive bisection.
	commitLen int
	// For cause bisection: Oldest commit returned by bisection.
	// For fix bisection: Newest commit returned by bisection.
	oldestLatest int
	// The commit introducing the bug.
	// If empty, the bug is assumed to exist from the beginning.
	introduced string
	// The commit fixing the bug.
	// If empty, the bug is never fixed.
	fixCommit string

	baselineConfig  string
	resultingConfig string
	crossTree       bool
	noFakeHashTest  bool

	extraTest func(t *testing.T, res *Result)
}

var bisectionTests = []BisectionTest{
	// Tests that bisection returns the correct cause commit.
	{
		name:        "cause-finds-cause",
		startCommit: 905,
		commitLen:   1,
		expectRep:   true,
		introduced:  "602",
		extraTest: func(t *testing.T, res *Result) {
			assert.Greater(t, res.Confidence, 0.99)
		},
	},
	{
		name:        "cause-finds-cause-flaky",
		startCommit: 905,
		commitLen:   1,
		expectRep:   true,
		flaky:       true,
		introduced:  "605",
		extraTest: func(t *testing.T, res *Result) {
			// False negative probability of each run is ~4%.
			// We get three "good" results, so our accumulated confidence is ~85%.
			assert.Less(t, res.Confidence, 0.9)
			assert.Greater(t, res.Confidence, 0.8)
		},
	},
	// Test bisection returns correct cause with different baseline/config combinations.
	{
		name:            "cause-finds-cause-baseline-repro",
		startCommit:     905,
		commitLen:       1,
		expectRep:       true,
		introduced:      "602",
		baselineConfig:  "baseline-repro",
		resultingConfig: "baseline-repro",
	},
	{
		name:            "cause-finds-cause-baseline-does-not-repro",
		startCommit:     905,
		commitLen:       1,
		expectRep:       true,
		introduced:      "602",
		baselineConfig:  "baseline-not-reproducing",
		resultingConfig: "original config",
	},
	{
		name:            "cause-finds-cause-baseline-fails",
		startCommit:     905,
		commitLen:       1,
		expectRep:       true,
		introduced:      "602",
		baselineConfig:  "baseline-fails",
		resultingConfig: "original config",
	},
	{
		name:            "cause-finds-cause-baseline-skip",
		startCommit:     905,
		commitLen:       1,
		expectRep:       true,
		introduced:      "602",
		baselineConfig:  "baseline-skip",
		resultingConfig: "original config",
	},
	{
		name:            "cause-finds-cause-minimize-succeeds",
		startCommit:     905,
		commitLen:       1,
		expectRep:       true,
		introduced:      "602",
		baselineConfig:  "minimize-succeeds",
		resultingConfig: "new-minimized-config",
	},
	{
		name:           "cause-finds-cause-minimize-fails",
		startCommit:    905,
		baselineConfig: "minimize-fails",
		expectErr:      true,
	},
	{
		name:            "config-minimize-same-hash",
		startCommit:     905,
		commitLen:       1,
		expectRep:       true,
		introduced:      "905",
		sameBinaryStart: 904,
		sameBinaryEnd:   905,
		noopChange:      true,
		baselineConfig:  "minimize-succeeds",
		resultingConfig: "new-minimized-config",
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
		oldestLatest: 400,
	},
	// Tests that more than 1 commit is returned when cause bisection is inconclusive.
	{
		name:        "cause-inconclusive",
		startCommit: 802,
		brokenStart: 500,
		brokenEnd:   700,
		commitLen:   15,
		introduced:  "605",
	},
	// All releases are build broken.
	{
		name:        "all-releases-broken",
		startCommit: 802,
		brokenStart: 100,
		brokenEnd:   800,
		// We mark these as failed, because build/boot failures of ancient releases are unlikely to get fixed
		// without manual intervention by syz-ci admins.
		commitLen: 0,
		expectRep: false,
		expectErr: true,
	},
	// Tests that bisection returns the correct fix commit.
	{
		name:        "fix-finds-fix",
		fix:         true,
		startCommit: 400,
		commitLen:   1,
		fixCommit:   "500",
		isRelease:   true,
	},
	// Tests that we do not confuse revisions where the bug was not yet introduced and where it's fixed.
	// In this case, we have a 700-790-791-792-804 branch, which will be visited during bisection.
	// As the faulty commit 704 is not reachable from there, kernel wouldn't crash and, without the
	// special care, we'd incorrectly designate "790" as the fix commit.
	// See #4117.
	{
		name:        "fix-after-bug",
		fix:         true,
		startCommit: 802,
		commitLen:   1,
		fixCommit:   "803",
		introduced:  "704",
	},
	// Tests that bisection returns the correct fix commit despite SYZFATAL.
	{
		name:             "fix-finds-fix-despite-syzfatal",
		fix:              true,
		startCommit:      400,
		injectSyzFailure: true,
		commitLen:        1,
		fixCommit:        "500",
		isRelease:        true,
	},
	// Tests that bisection returns the correct fix commit despite `lost connection to test machine`.
	{
		name:                 "fix-finds-fix-despite-lost-connection",
		fix:                  true,
		startCommit:          400,
		injectLostConnection: true,
		commitLen:            1,
		fixCommit:            "500",
		isRelease:            true,
	},
	// Tests that bisection returns the correct fix commit in case of SYZFATAL.
	{
		name:        "fix-finds-fix-for-syzfatal",
		fix:         true,
		startCommit: 400,
		reportType:  crash.SyzFailure,
		commitLen:   1,
		fixCommit:   "500",
		isRelease:   true,
	},
	// Tests that fix bisection returns error when crash does not reproduce
	// on the original commit.
	{
		name:        "fix-does-not-repro",
		fix:         true,
		startCommit: 905,
		expectErr:   true,
		fixCommit:   "900",
	},
	// Tests that no commits are returned when HEAD is build broken.
	// Fix bisection equivalent of all-releases-broken.
	{
		name:         "fix-HEAD-broken",
		fix:          true,
		startCommit:  400,
		brokenStart:  500,
		brokenEnd:    1000,
		fixCommit:    "1000",
		oldestLatest: 905,
		// We mark these as re-tryable, because build/boot failures of HEAD will also be caught during regular fuzzing
		// and are fixed by kernel devs or syz-ci admins in a timely manner.
		commitLen: 0,
		expectRep: true,
		expectErr: false,
	},
	// Tests that no commits are returned when crash occurs on HEAD
	// for fix bisection.
	{
		name:         "fix-HEAD-crashes",
		fix:          true,
		startCommit:  400,
		fixCommit:    "1000",
		oldestLatest: 905,
		commitLen:    0,
		expectRep:    true,
		expectErr:    false,
	},
	// Tests that more than 1 commit is returned when fix bisection is inconclusive.
	{
		name:        "fix-inconclusive",
		fix:         true,
		startCommit: 500,
		brokenStart: 600,
		brokenEnd:   700,
		commitLen:   9,
		fixCommit:   "601",
	},
	{
		name:            "cause-same-binary",
		startCommit:     905,
		commitLen:       1,
		expectRep:       true,
		introduced:      "503",
		sameBinaryStart: 502,
		sameBinaryEnd:   503,
		noopChange:      true,
	},
	{
		name:            "cause-same-binary-off-by-one",
		startCommit:     905,
		commitLen:       1,
		expectRep:       true,
		introduced:      "503",
		sameBinaryStart: 400,
		sameBinaryEnd:   502,
	},
	{
		name:            "cause-same-binary-off-by-one-2",
		startCommit:     905,
		commitLen:       1,
		expectRep:       true,
		introduced:      "503",
		sameBinaryStart: 503,
		sameBinaryEnd:   905,
	},
	{
		name:            "fix-same-binary",
		fix:             true,
		startCommit:     400,
		commitLen:       1,
		fixCommit:       "503",
		sameBinaryStart: 502,
		sameBinaryEnd:   504,
		noopChange:      true,
	},
	{
		name:            "cause-same-binary-release1",
		startCommit:     905,
		commitLen:       1,
		expectRep:       true,
		introduced:      "500",
		sameBinaryStart: 405,
		sameBinaryEnd:   500,
		noopChange:      true,
		isRelease:       true,
	},
	{
		name:            "cause-same-binary-release2",
		startCommit:     905,
		commitLen:       1,
		expectRep:       true,
		introduced:      "501",
		sameBinaryStart: 500,
		sameBinaryEnd:   501,
		noopChange:      true,
	},
	{
		name:            "cause-same-binary-release3",
		startCommit:     905,
		commitLen:       1,
		expectRep:       true,
		introduced:      "405",
		sameBinaryStart: 404,
		sameBinaryEnd:   405,
		noopChange:      true,
	},
	{
		name:            "fix-same-binary-last",
		fix:             true,
		startCommit:     400,
		commitLen:       1,
		fixCommit:       "905",
		sameBinaryStart: 904,
		sameBinaryEnd:   905,
		noopChange:      true,
	},
	{
		name:        "fix-release",
		fix:         true,
		startCommit: 400,
		commitLen:   1,
		fixCommit:   "900",
		isRelease:   true,
	},
	{
		name:            "cause-not-in-previous-release-issue-1527",
		startCommit:     905,
		introduced:      "650",
		commitLen:       1,
		expectRep:       true,
		sameBinaryStart: 500,
		sameBinaryEnd:   650,
		noopChange:      true,
	},
	{
		name:          "cause-infra-problems",
		startCommit:   905,
		expectRep:     false,
		expectErr:     true,
		expectErrType: &build.InfraError{},
		infraErrStart: 600,
		infraErrEnd:   800,
		introduced:    "602",
	},
	{
		name:              "fix-cross-tree",
		fix:               true,
		startCommit:       851,
		startCommitBranch: "v8-branch",
		commitLen:         1,
		crossTree:         true,
		fixCommit:         "903",
	},
	{
		name:              "cause-finds-other-branch-commit",
		startCommit:       852,
		startCommitBranch: "v8-branch",
		commitLen:         1,
		expectRep:         true,
		introduced:        "602",
		noFakeHashTest:    true,
	},
	{
		// There's no fix for the bug because it was introduced
		// in another tree.
		name:              "no-fix-cross-tree",
		fix:               true,
		startCommit:       852,
		startCommitBranch: "v8-branch",
		commitLen:         0,
		crossTree:         true,
		introduced:        "851",
		oldestLatest:      800,
	},
	{
		// We are unable to test the merge base commit.
		name:              "fix-cross-tree-broken-start",
		fix:               true,
		startCommit:       851,
		startCommitBranch: "v8-branch",
		commitLen:         0,
		crossTree:         true,
		fixCommit:         "903",
		brokenStart:       800,
		brokenEnd:         800,
		oldestLatest:      800,
	},
}

func TestBisectionResults(t *testing.T) {
	t.Parallel()
	// Creating new repos takes majority of the test time,
	// so we reuse them across tests.
	repoCache := make(chan string, len(bisectionTests))
	t.Run("group", func(tt *testing.T) {
		for _, test := range bisectionTests {
			tt.Run(test.name, func(t *testing.T) {
				t.Parallel()
				checkTest(t, test)
				repoDir := ""
				select {
				case repoDir = <-repoCache:
				default:
					repoDir = createTestRepo(tt)
				}
				defer func() {
					repoCache <- repoDir
				}()
				testBisection(t, repoDir, test)
			})
		}
	})
}

func checkTest(t *testing.T, test BisectionTest) {
	if test.expectErr &&
		(test.commitLen != 0 ||
			test.expectRep ||
			test.oldestLatest != 0 ||
			test.resultingConfig != "") {
		t.Fatalf("expecting non-default values on error")
	}
	if !test.expectErr && test.baselineConfig != "" && test.resultingConfig == "" {
		t.Fatalf("specify resultingConfig with baselineConfig")
	}
	if test.brokenStart > test.brokenEnd {
		t.Fatalf("bad broken start/end: %v/%v",
			test.brokenStart, test.brokenEnd)
	}
	if test.sameBinaryStart > test.sameBinaryEnd {
		t.Fatalf("bad same binary start/end: %v/%v",
			test.sameBinaryStart, test.sameBinaryEnd)
	}
}

func crashErrors(crashing, nonCrashing int, title string, typ crash.Type) []instance.EnvTestResult {
	var ret []instance.EnvTestResult
	for i := 0; i < crashing; i++ {
		ret = append(ret, instance.EnvTestResult{
			Error: &instance.CrashError{
				Report: &report.Report{
					Title: fmt.Sprintf("crashes at %v", title),
					Type:  typ,
				},
			},
		})
	}
	for i := 0; i < nonCrashing; i++ {
		ret = append(ret, instance.EnvTestResult{})
	}
	return ret
}

func TestBisectVerdict(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		flaky   bool
		total   int
		good    int
		bad     int
		infra   int
		skip    int
		verdict vcs.BisectResult
		abort   bool
	}{
		{
			name:  "bad-but-many-infra",
			total: 10,
			bad:   1,
			infra: 8,
			skip:  1,
			abort: true,
		},
		{
			name:    "many-good-and-infra",
			total:   10,
			good:    5,
			infra:   3,
			skip:    2,
			verdict: vcs.BisectGood,
		},
		{
			name:    "many-total-and-infra",
			total:   10,
			good:    4,
			bad:     2,
			infra:   2,
			skip:    2,
			verdict: vcs.BisectBad,
		},
		{
			name:    "too-many-skips",
			total:   10,
			good:    2,
			bad:     2,
			infra:   3,
			skip:    3,
			verdict: vcs.BisectSkip,
		},
		{
			name:  "flaky-need-more-good",
			flaky: true,
			total: 20,
			// For flaky bisections, we'd want 15.
			good:    10,
			infra:   3,
			skip:    7,
			verdict: vcs.BisectSkip,
		},
		{
			name:    "flaky-enough-good",
			flaky:   true,
			total:   20,
			good:    15,
			infra:   3,
			skip:    2,
			verdict: vcs.BisectGood,
		},
		{
			name:  "flaky-too-many-skips",
			flaky: true,
			total: 20,
			// We want (good+bad) take at least 50%.
			good:    6,
			bad:     1,
			infra:   0,
			skip:    13,
			verdict: vcs.BisectSkip,
		},
		{
			name:    "flaky-many-skips",
			flaky:   true,
			total:   20,
			good:    7,
			bad:     3,
			infra:   0,
			skip:    10,
			verdict: vcs.BisectBad,
		},
		{
			name:    "outlier-bad",
			total:   10,
			good:    9,
			bad:     1,
			infra:   0,
			skip:    0,
			verdict: vcs.BisectSkip,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			sum := test.good + test.bad + test.infra + test.skip
			assert.Equal(t, test.total, sum)
			env := &env{
				cfg: &Config{
					Trace: &debugtracer.NullTracer{},
				},
				flaky: test.flaky,
			}
			ret, err := env.bisectionDecision(test.total, test.bad, test.good, test.infra)
			assert.Equal(t, test.abort, err != nil)
			if !test.abort {
				assert.Equal(t, test.verdict, ret)
			}
		})
	}
}

// nolint: dupl
func TestMostFrequentReport(t *testing.T) {
	tests := []struct {
		name    string
		reports []*report.Report
		report  string
		types   []crash.Type
		other   bool
	}{
		{
			name: "one infrequent",
			reports: []*report.Report{
				{Title: "A", Type: crash.KASANRead},
				{Title: "B", Type: crash.KASANRead},
				{Title: "C", Type: crash.Bug},
				{Title: "D", Type: crash.KASANRead},
				{Title: "E", Type: crash.Bug},
				{Title: "F", Type: crash.KASANRead},
				{Title: "G", Type: crash.LockdepBug},
			},
			// LockdepBug was too infrequent.
			types:  []crash.Type{crash.KASANRead, crash.Bug},
			report: "A",
			other:  true,
		},
		{
			name: "ignore hangs",
			reports: []*report.Report{
				{Title: "A", Type: crash.KASANRead},
				{Title: "B", Type: crash.KASANRead},
				{Title: "C", Type: crash.Hang},
				{Title: "D", Type: crash.KASANRead},
				{Title: "E", Type: crash.Hang},
				{Title: "F", Type: crash.Hang},
				{Title: "G", Type: crash.Warning},
			},
			// Hang is not a preferred report type.
			types:  []crash.Type{crash.KASANRead, crash.Warning},
			report: "A",
			other:  true,
		},
		{
			name: "take hangs",
			reports: []*report.Report{
				{Title: "A", Type: crash.KASANRead},
				{Title: "B", Type: crash.KASANRead},
				{Title: "C", Type: crash.Hang},
				{Title: "D", Type: crash.Hang},
				{Title: "E", Type: crash.Hang},
				{Title: "F", Type: crash.Hang},
			},
			// There are so many Hangs that we can't ignore it.
			types:  []crash.Type{crash.Hang, crash.KASANRead},
			report: "C",
		},
		{
			name: "take unknown",
			reports: []*report.Report{
				{Title: "A", Type: crash.UnknownType},
				{Title: "B", Type: crash.UnknownType},
				{Title: "C", Type: crash.Hang},
				{Title: "D", Type: crash.UnknownType},
				{Title: "E", Type: crash.Hang},
				{Title: "F", Type: crash.UnknownType},
			},
			// UnknownType is also a type.
			types:  []crash.Type{crash.UnknownType},
			report: "A",
			other:  true,
		},
		{
			name: "do not take lost connection",
			reports: []*report.Report{
				{Title: "A", Type: crash.LostConnection},
				{Title: "B", Type: crash.Warning},
				{Title: "C", Type: crash.LostConnection},
				{Title: "D", Type: crash.Warning},
				{Title: "E", Type: crash.LostConnection},
				{Title: "F", Type: crash.Warning},
			},
			types:  []crash.Type{crash.Warning},
			report: "B",
			other:  true,
		},
		{
			name: "only lost connection",
			reports: []*report.Report{
				{Title: "A", Type: crash.LostConnection},
				{Title: "B", Type: crash.LostConnection},
				{Title: "C", Type: crash.LostConnection},
				{Title: "D", Type: crash.LostConnection},
				{Title: "E", Type: crash.LostConnection},
				{Title: "F", Type: crash.LostConnection},
			},
			types:  []crash.Type{crash.LostConnection},
			report: "A",
			other:  false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			rep, types, other := mostFrequentReports(test.reports)
			assert.ElementsMatch(t, types, test.types)
			assert.Equal(t, rep.Title, test.report)
			assert.Equal(t, other, test.other)
		})
	}
}

func TestPickReleaseTags(t *testing.T) {
	tests := []struct {
		name string
		tags []string
		ret  []string
	}{
		{
			name: "upstream-clang",
			tags: []string{
				"v6.5", "v6.4", "v6.3", "v6.2", "v6.1", "v6.0", "v5.19",
				"v5.18", "v5.17", "v5.16", "v5.15", "v5.14", "v5.13",
				"v5.12", "v5.11", "v5.10", "v5.9", "v5.8", "v5.7", "v5.6",
				"v5.5", "v5.4",
			},
			ret: []string{
				"v6.5", "v6.4", "v6.3", "v6.1", "v5.19", "v5.17", "v5.15",
				"v5.13", "v5.10", "v5.7", "v5.4",
			},
		},
		{
			name: "upstream-gcc",
			tags: []string{
				"v6.5", "v6.4", "v6.3", "v6.2", "v6.1", "v6.0", "v5.19",
				"v5.18", "v5.17", "v5.16", "v5.15", "v5.14", "v5.13",
				"v5.12", "v5.11", "v5.10", "v5.9", "v5.8", "v5.7", "v5.6",
				"v5.5", "v5.4", "v5.3", "v5.2", "v5.1", "v5.0", "v4.20", "v4.19",
				"v4.18",
			},
			ret: []string{
				"v6.5", "v6.4", "v6.3", "v6.1", "v5.19", "v5.17", "v5.15",
				"v5.13", "v5.10", "v5.7", "v5.4", "v5.1", "v4.19", "v4.18",
			},
		},
		{
			name: "lts",
			tags: []string{
				"v5.15.10", "v5.15.9", "v5.15.8", "v5.15.7", "v5.15.6",
				"v5.15.5", "v5.15.4", "v5.15.3", "v5.15.2", "v5.15.1",
				"v5.15", "v5.14", "v5.13", "v5.12", "v5.11", "v5.10",
				"v5.9", "v5.8", "v5.7", "v5.6", "v5.5", "v5.4",
			},
			ret: []string{
				"v5.15.10", "v5.15.9", "v5.15.5", "v5.15", "v5.14", "v5.13",
				"v5.11", "v5.9", "v5.7", "v5.5", "v5.4",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ret := pickReleaseTags(append([]string{}, test.tags...))
			assert.Equal(t, test.ret, ret)
		})
	}
}
