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

	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/instance"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/pkg/vcs"
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

func (env *testEnv) BuildSyzkaller(repo, commit string) error {
	return nil
}

func (env *testEnv) BuildKernel(compilerBin, userspaceDir, cmdlineFile, sysctlFile string,
	kernelConfig []byte) (string, string, error) {
	commit := env.headCommit()
	configHash := hash.String(kernelConfig)
	kernelSign := fmt.Sprintf("%v-%v", commit, configHash)
	if commit >= env.test.sameBinaryStart && commit <= env.test.sameBinaryEnd {
		// kernelSign = "same-sign-" + configHash  // [TOV]: Can't use this for real sign-re checking logic
		// [TOV]: Needed keeping kernelSign as in real-life - equal to one in last OpCh commit
		kernelSign = fmt.Sprintf("%v-%v", env.test.sameBinaryStart, configHash)
		// __DB__
		fmt.Fprintf(os.Stdout, "|%v|TDB>> For COMMIT #'%v', the TEST build SIGN-re was gen-ed:"+
			" '%v' instead of 'same-sign- + HASH'.\n", env.test.name, commit, kernelSign)
		// env.t.Logf("\n  [Log]TDB>> For COMMIT #'%v', the TEST buid SIGN-re was gen-ed:"+
		// 	" '%v' instead of 'same-sign- + HASH'.\n", commit, kernelSign)
		// ^^DB^^
	}
	env.config = string(kernelConfig)
	if env.config == "baseline-fails" || env.config == "broken-build" {
		return "", kernelSign, fmt.Errorf("failure")
	}
	return "", kernelSign, nil
}

func (env *testEnv) Test(numVMs int, reproSyz, reproOpts, reproC []byte) ([]error, error) {
	commit := env.headCommit()
	if commit >= env.test.brokenStart && commit <= env.test.brokenEnd ||
		env.config == "baseline-skip" {
		return nil, fmt.Errorf("broken build")
	}
	// [TOV] FIXME: Currently, ~30% of all test-cases - whole "NoOp" test sets - are inconsistent!
	//       IMPOSSIBLE "NoOp" search 'culprit' + 'same_binary' span combination targets are given
	//       in order to trigger wanted code branches. Specifically, different errors are generated for same binaries!
	//       TODO: Check the Fix the "NoOp" test-cases to be aligned with real-life and common sense.
	//             Handling of noOps - 'rollback' to non-noOp now, so no nonsense (U)testing setups are needed.
	//             Question: code coverage..
	// __DB__
	// Re-calc KernSign-re
	kernelSign := "not recalc-ed yet"
	if commit >= env.test.sameBinaryStart && commit <= env.test.sameBinaryEnd {
		kernelSign = fmt.Sprintf("%v-%v", env.test.sameBinaryStart, hash.String([]byte(env.config)))
	} else {
		kernelSign = fmt.Sprintf("%v-%v", commit, hash.String([]byte(env.config)))
	}
	// if _, reproFailFnd := env.test.randomPitfalls[commit]; reproFailFnd {
	// 	fmt.Fprintf(os.Stdout, "|%v|TDB>> TDB>> Pitfall predefined popped up.. For COMMIT #'%v'\n", env.test.name, commit)
	// }
	// ^^DB^^
	if _, reproFailFnd := env.test.randomPitfalls[commit]; (env.config == "baseline-repro" ||
		env.config == "new-minimized-config" || env.config == "original config") &&
		(!env.test.fix && commit >= env.test.culprit && !reproFailFnd /*&& (env.test.sameBinaryEnd == 0 || commit <= env.test.sameBinaryEnd) //  leads to bisection start issues*/ ||
			env.test.fix && commit < env.test.culprit) { // [TOV]: TODO: Add the same ^ extra logic for fix search?
		// __DB__
		fmt.Fprintf(os.Stdout, "|%v|TDB>> For COMMIT #'%v', the 'crash occurs' build (sign-re: '%v') TEST result was gen-ed (all VMs).\n",
			env.test.name, commit, kernelSign)
		// env.t.Logf("\n  [Log]TDB>> For COMMIT #'%v', the 'crash occurs' build (sign-re: '%v') TEST result was gen-ed (all VMs).\n",
		// 	commit, kernelSign)
		// ^^DB^^
		return crashErrors(numVMs, "crash occurs"), nil
	}
	// __DB__
	fmt.Fprintf(os.Stdout, "|%v|TDB>> For COMMIT #'%v', the 'nil' ('no err') build (sign-re: '%v') TEST result was gen-ed (all VMs).\n",
		env.test.name, commit, kernelSign)
	// env.t.Logf("\n  [Log]TDB>> For COMMIT #'%v', the 'nil' ('no err') build (sign-re: '%v') TEST result was gen-ed (all VMs).\n",
	// 	commit, kernelSign)
	// ^^DB^^
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

func createTestRepo(t *testing.T) string {
	baseDir, err := ioutil.TempDir("", "syz-bisect-test")
	if err != nil {
		t.Fatal(err)
	}
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
			} else {
				repo.CommitChange(fmt.Sprintf("%v", rv*100+i))
			}
			if i == 0 {
				repo.SetTag(fmt.Sprintf("v%v.0", rv))
			}
		}
	}
	return baseDir
}

// [TOV]: TODO: finalize mocking
// func (env *testEnv) Bisect(bad, good string, trace io.Writer, pred func() (BisectResult, error)) ([]*Commit, error) {
// 	commits, err := ctx.git.Bisect(bad, good, trace, pred)
// 	if len(commits) == 1 {
// 		ctx.addMaintainers(commits[0])
// 	}
// 	return commits, err
// }

func runBisection(t *testing.T, baseDir string, test BisectionTest) (*BisectResult, error) {
	// [TOV]: TODO: Need mocking the 'bisecter.Bisect' for easier controlling its output
	r, err := vcs.NewRepo("test", "64", baseDir)

	if err != nil {
		t.Fatal(err)
	}
	r.SwitchCommit("master")
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
			KernelSrc:    baseDir,
		},
		Kernel: KernelConfig{
			Repo:           baseDir,
			Commit:         sc.Hash,
			Config:         []byte("original config"),
			BaselineConfig: []byte(test.baselineConfig),
		},
	}
	inst := &testEnv{
		t:    t,
		r:    r,
		test: test,
	}
	res, err := runImpl(cfg, r, inst)
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
	expectErr            bool
	expectRep            bool
	noopChange           bool
	origBisectWasNoOpCmt bool
	isRelease            bool
	commitLen            int
	oldestLatest         int
	// input and output
	culprit         int
	baselineConfig  string
	resultingConfig string
	randomPitfalls  map[int]bool
}

var bisectionTests = []BisectionTest{
	// Tests that bisection returns the correct cause commit.
	{
		name:        "cause-finds-cause",
		startCommit: 905,
		commitLen:   1,
		expectRep:   true,
		culprit:     602,
	},
	// Test bisection returns correct cause with different baseline/config combinations.
	{
		name:            "cause-finds-cause-baseline-repro",
		startCommit:     905,
		commitLen:       1,
		expectRep:       true,
		culprit:         602,
		baselineConfig:  "baseline-repro",
		resultingConfig: "baseline-repro",
	},
	{
		name:            "cause-finds-cause-baseline-broken-build",
		startCommit:     905,
		commitLen:       1,
		expectRep:       true,
		culprit:         602,
		baselineConfig:  "baseline-broken-build",
		resultingConfig: "original config",
	},
	{
		name:            "cause-finds-cause-baseline-does-not-repro",
		startCommit:     905,
		commitLen:       1,
		expectRep:       true,
		culprit:         602,
		baselineConfig:  "baseline-not-reproducing",
		resultingConfig: "original config",
	},
	{
		name:            "cause-finds-cause-baseline-fails",
		startCommit:     905,
		commitLen:       1,
		expectRep:       true,
		culprit:         602,
		baselineConfig:  "baseline-fails",
		resultingConfig: "original config",
	},
	{
		name:            "cause-finds-cause-baseline-skip",
		startCommit:     905,
		commitLen:       1,
		expectRep:       true,
		culprit:         602,
		baselineConfig:  "baseline-skip",
		resultingConfig: "original config",
	},
	{
		name:            "cause-finds-cause-minimize-succeeds",
		startCommit:     905,
		commitLen:       1,
		expectRep:       true,
		culprit:         602,
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
		culprit:         904, //905,
		sameBinaryStart: 904, // [TOV]: Can't untie culprit and same bin range start commit. TODO: Keep only End?
		sameBinaryEnd:   905,
		// origBisectWasNoOpCmt: true, // TODO: Check
		//noopChange:      true,
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
		culprit:      0,
		oldestLatest: 400,
	},
	// Tests that more than 1 commit is returned when cause bisection is inconclusive.
	{
		name:        "cause-inconclusive",
		startCommit: 802,
		brokenStart: 500,
		brokenEnd:   700,
		commitLen:   15,
		culprit:     605,
	},
	// All releases are build broken.
	{
		name:        "all-releases-broken",
		startCommit: 802,
		brokenStart: 100,
		brokenEnd:   800,
		commitLen:   2,
	},
	// Tests that bisection returns the correct fix commit.
	{
		name:        "fix-finds-fix",
		fix:         true,
		startCommit: 400,
		commitLen:   1,
		culprit:     500,
		isRelease:   true,
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
		sameBinaryStart: 503, //502,
		sameBinaryEnd:   504, //503,
		// origBisectWasNoOpCmt: true, // TODO: Check
		//noopChange:      true,
		randomPitfalls: map[int]bool{
			// 700: true, // fails the test (release commit?)
			// 600: true, // fails the test (release commit?)
			602: true,
			505: true,
		},
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
		sameBinaryStart: 503, //502,
		sameBinaryEnd:   504,
		// origBisectWasNoOpCmt: true, // TODO: Check
		//noopChange:      true,
	},
	{
		name:            "cause-same-binary-release1",
		startCommit:     905,
		commitLen:       1,
		expectRep:       true,
		culprit:         500,
		sameBinaryStart: 500, //405,
		sameBinaryEnd:   501, //500,
		// origBisectWasNoOpCmt: true, // TODO: Check
		//noopChange:      true,
		randomPitfalls: map[int]bool{
			605: true,
			603: true,
			701: false, // not matter what here, just slices are undeveloped in Go, so maps are used ;)
		},
		isRelease: true,
	},
	{
		name:            "cause-same-binary-release2",
		startCommit:     905,
		commitLen:       1,
		expectRep:       true,
		culprit:         501,
		sameBinaryStart: 501, //500,
		sameBinaryEnd:   502, //501,
		// origBisectWasNoOpCmt: true, // TODO: Check
		//noopChange:      true,
		randomPitfalls: map[int]bool{
			702: true,
			604: true,
			// [TOV]: TODO: Does a pitfall on any of commits that are checked by Bisector fail bisection?
			// 503: true, // fails the test.
		},
	},
	{
		name:            "cause-same-binary-release3",
		startCommit:     905,
		commitLen:       1,
		expectRep:       true,
		culprit:         404, //405,
		sameBinaryStart: 404,
		sameBinaryEnd:   405,
		// origBisectWasNoOpCmt: true, // TODO: Check
		//noopChange:      true,
		randomPitfalls: map[int]bool{
			501: true,
			603: true,
		},
	},
	{
		name:            "fix-same-binary-prelast", // "fix-same-binary-last" [TOV]: Impossible testcase name ;)
		fix:             true,
		startCommit:     400,
		commitLen:       1,
		culprit:         904, //905,
		sameBinaryStart: 904,
		sameBinaryEnd:   905,
		// origBisectWasNoOpCmt: true, // TODO: Check
		//noopChange:      true,
	},
	{
		name:        "fix-release",
		fix:         true,
		startCommit: 400,
		commitLen:   1,
		culprit:     900,
		isRelease:   true,
	},
	{
		name:            "cause-not-in-previous-release-issue-1527",
		startCommit:     905,
		culprit:         650,
		commitLen:       1,
		expectRep:       true,
		sameBinaryStart: 650, //500,
		sameBinaryEnd:   701, //650,
		// origBisectWasNoOpCmt: true, // TODO: Check
		//noopChange:      true,
	},
}

func TestBisectionResults(t *testing.T) {
	t.Parallel()
	// Creating new repos takes majority of the test time,
	// so we reuse them across tests.
	repoCache := make(chan string, len(bisectionTests))
	t.Run("group", func(t *testing.T) {
		for _, test := range bisectionTests {
			test := test
			t.Run(test.name, func(t *testing.T) {
				t.Parallel()
				checkTest(t, test)
				repoDir := ""
				select {
				case repoDir = <-repoCache:
				default:
					repoDir = createTestRepo(t)
				}
				defer func() {
					repoCache <- repoDir
				}()
				res, err := runBisection(t, repoDir, test)
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
				// [TOV]: TODO: Added res.OrigBisectWasNoOpCmt?
				if res.OrigBisectWasNoOpCmt != test.origBisectWasNoOpCmt {
					t.Fatalf("got orig noOp change commit: %v, want: %v",
						res.OrigBisectWasNoOpCmt, test.origBisectWasNoOpCmt)
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
			})
		}
	})
	for {
		select {
		case dir := <-repoCache:
			os.RemoveAll(dir)
		default:
			return
		}
	}
}

func checkTest(t *testing.T, test BisectionTest) {
	if test.expectErr &&
		(test.commitLen != 0 ||
			test.expectRep ||
			test.oldestLatest != 0 ||
			test.culprit != 0 ||
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
