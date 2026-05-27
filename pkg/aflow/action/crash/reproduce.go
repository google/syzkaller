// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package crash

import (
	"cmp"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/build"
	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/instance"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/pkg/symbolizer"
	"github.com/google/syzkaller/sys/targets"
)

var ErrDidNotCrash = errors.New("reproducer did not crash")

// Reproduce action tries to reproduce a crash with the given reproducer,
// and outputs the resulting crash report.
// If the reproducer does not trigger a crash, action fails.
var Reproduce = aflow.NewFuncAction("crash-reproducer", ReproduceFunc)

type ReproduceArgs struct {
	TargetArch   string
	Syzkaller    string
	Image        string
	Type         string
	VM           json.RawMessage
	ReproOpts    string
	ReproSyz     string
	ReproC       string
	KernelSrc    string
	KernelObj    string
	KernelCommit string
	KernelConfig string
	StraceBin    string
	NeedStrace   bool
}

type reproduceResult struct {
	ReproducedBugTitle       string
	ReproducedCrashReport    string
	OtherCrashReports        []string
	ReproducedFaultInjection string
}

type RunTestResult struct {
	// Returned if the program caused a kernel crash.
	Report *report.Report
	// Other crash reports triggered during reproduction, excluding the main Report.
	OtherReports []*report.Report
	// Returned if the kernel failed to boot or function properly
	// (Report is not returned in this case).
	BootError string
	// Extracted fault injection report for the test run, if any.
	FaultInjection string
	// Per-call coverage, if requested with collectCoverage
	// and the kernel has not crashed.
	Coverage [][]symbolizer.Frame
	// Raw console output from the VM run.
	ConsoleOutput string
}

// RunTest boots the kernel and runs a single test program.
func RunTest(args ReproduceArgs, workdir string, collectCoverage bool) (RunTestResult, error) {
	res := RunTestResult{}
	if args.Type != "qemu" {
		return res, errors.New("RunTest: only qemu VM type is supported")
	}
	if collectCoverage && args.ReproSyz == "" {
		return res, errors.New("RunTest: coverage collection requires a syzkaller program")
	}

	var vmConfig map[string]any
	if err := json.Unmarshal(args.VM, &vmConfig); err != nil {
		return res, fmt.Errorf("failed to parse VM config: %w", err)
	}
	targetArch := args.TargetArch
	vmConfig["kernel"] = filepath.Join(args.KernelObj, filepath.FromSlash(build.LinuxKernelImage(targetArch)))
	vmCfg, err := json.Marshal(vmConfig)
	if err != nil {
		return res, fmt.Errorf("failed to serialize VM config: %w", err)
	}

	cfg := mgrconfig.DefaultValues()
	cfg.RawTarget = targets.Linux + "/" + targetArch
	cfg.Workdir = workdir
	cfg.Syzkaller = args.Syzkaller
	cfg.KernelObj = args.KernelObj
	cfg.KernelSrc = args.KernelSrc
	cfg.Image = args.Image
	cfg.Type = args.Type
	cfg.VM = vmCfg
	if args.NeedStrace && args.StraceBin != "" {
		cfg.StraceBin = args.StraceBin
		cfg.StraceBinOnTarget = false
	}
	if err := mgrconfig.SetTargets(cfg); err != nil {
		return res, err
	}
	if err := mgrconfig.Complete(cfg); err != nil {
		return res, err
	}
	if args.ReproOpts == "" {
		args.ReproOpts = string(csource.DefaultOpts(cfg).Serialize())
	}
	env, err := instance.NewEnv(cfg, nil, nil)
	if err != nil {
		return res, err
	}
	crashReporter, err := report.NewReporter(cfg)
	if err != nil {
		return res, fmt.Errorf("failed to create crash reporter: %w", err)
	}

	runner := &reproRunner{
		env:             env,
		args:            args,
		collectCoverage: collectCoverage,
	}

	validResults, err := instance.CollectRuns(runner.Test, instance.CollectRunsOpts{
		WantValid: 3,
		MaxTotal:  6,
		MaxVMs:    3,
	})
	if err != nil {
		return res, err
	}

	return aggregateTestResults(validResults, crashReporter, args.KernelObj, targetArch)
}

type reproRunner struct {
	env             instance.Env
	args            ReproduceArgs
	collectCoverage bool
}

func (r *reproRunner) Test(numVMs int) ([]instance.EnvTestResult, error) {
	results, err := r.env.Test(numVMs, []byte(r.args.ReproSyz), []byte(r.args.ReproOpts),
		[]byte(r.args.ReproC), r.collectCoverage)
	if err != nil {
		return nil, err
	}
	if len(results) == 0 {
		return nil, fmt.Errorf("env.Test returned no results")
	}
	return results, nil
}

func aggregateTestResults(validResults []instance.EnvTestResult,
	crashReporter *report.Reporter, kernelObj, targetArch string) (RunTestResult, error) {
	var res RunTestResult
	if len(validResults) > 0 {
		res.ConsoleOutput = string(validResults[0].RawOutput)
	}

	type crashStat struct {
		report *report.Report
		count  int
	}
	crashes := make(map[string]*crashStat)
	var firstCoverage [][]uint64

	for _, result := range validResults {
		if result.Error == nil {
			if len(result.Coverage) > 0 && firstCoverage == nil {
				firstCoverage = result.Coverage
			}
			continue
		}

		var crashErr *instance.CrashError
		if errors.As(result.Error, &crashErr) {
			title := crashErr.Report.Title
			if stat, ok := crashes[title]; ok {
				stat.count++
			} else {
				crashes[title] = &crashStat{report: crashErr.Report, count: 1}
				if res.FaultInjection == "" {
					fi, _ := crashReporter.ExtractFaultInjectionInfo(result.RawOutput)
					res.FaultInjection = fi
				}
			}
			continue
		}

		var testErr *instance.TestError
		if errors.As(result.Error, &testErr) && res.BootError == "" {
			res.BootError = parseTestError(testErr)
		}
	}

	if len(crashes) > 0 {
		stats := slices.Collect(maps.Values(crashes))
		slices.SortFunc(stats, func(a, b *crashStat) int {
			if a.count != b.count {
				return b.count - a.count
			}
			return cmp.Compare(a.report.Title, b.report.Title)
		})
		res.Report = stats[0].report
		for i := 1; i < len(stats); i++ {
			res.OtherReports = append(res.OtherReports, stats[i].report)
		}
	}

	if res.Report == nil && res.BootError == "" && firstCoverage != nil {
		coverage, err := symbolize(targetArch, kernelObj, firstCoverage)
		if err != nil {
			return res, fmt.Errorf("failed to symbolize coverage: %w", err)
		}
		res.Coverage = coverage
	}

	return res, nil
}

func parseTestError(err *instance.TestError) string {
	what := "Basic kernel testing failed"
	if err.Boot {
		what = "Kernel failed to boot"
	}
	extraInfo := err.Output
	// Don't use TestError.Report for crashes like "lost connection" that don't have a report.
	if err.Report != nil && err.Report.Report != nil {
		extraInfo = err.Report.Report
	}
	return fmt.Sprintf("%v: %v\n%s", what, err.Title, extraInfo)
}

func ReproduceFuncWithCoverage(ctx *aflow.Context, args ReproduceArgs,
	collectCoverage bool) (reproduceResult, string, error) {
	imageData, err := os.ReadFile(args.Image)
	if err != nil {
		return reproduceResult{}, "", err
	}
	desc := fmt.Sprintf("kernel commit %v, kernel config hash %v, image hash %v,"+
		" vm %v, vm config hash %v, C repro hash %v, syz repro hash %v, opts hash %v, cov %v, version 6",
		args.KernelCommit, hash.String(args.KernelConfig), hash.String(imageData),
		args.Type, hash.String(args.VM), hash.String(args.ReproC),
		hash.String(args.ReproSyz), hash.String(args.ReproOpts), collectCoverage)
	type Cached struct {
		BugTitle       string
		Report         string
		OtherReports   []string
		FaultInjection string
		Error          string
		CoverageID     string
	}
	cached, err := aflow.CacheObject(ctx, "repro", desc, func() (Cached, error) {
		var res Cached
		workdir, err := ctx.TempDir()
		if err != nil {
			return res, err
		}
		testRes, err := RunTest(args, workdir, collectCoverage)
		if testRes.Report != nil {
			res.BugTitle = testRes.Report.Title
			res.Report = string(testRes.Report.Report)
		}
		for _, rep := range testRes.OtherReports {
			res.OtherReports = append(res.OtherReports, string(rep.Report))
		}
		res.FaultInjection = testRes.FaultInjection
		res.Error = testRes.BootError
		// If the reproducer crashes the kernel, the VM halts abruptly and coverage
		// often fails to flush, leaving testRes.Coverage empty. This is expected: we
		// generally only want diagnostics on reproducers that failed to crash.
		if err == nil && len(testRes.Coverage) > 0 {
			dir, err := ctx.Cache("coverage", desc, func(dir string) error {
				return osutil.WriteJSON(filepath.Join(dir, "coverage.json"), testRes.Coverage)
			})
			if err != nil {
				return res, err
			}
			res.CoverageID = filepath.Base(dir)
		}
		return res, err
	})
	if err != nil {
		return reproduceResult{}, "", err
	}
	if cached.Error != "" {
		return reproduceResult{}, "", errors.New(cached.Error)
	} else if cached.Report == "" && len(cached.OtherReports) == 0 {
		return reproduceResult{}, cached.CoverageID, aflow.FlowError(ErrDidNotCrash)
	}
	return reproduceResult{
		ReproducedBugTitle:       cached.BugTitle,
		ReproducedCrashReport:    cached.Report,
		OtherCrashReports:        cached.OtherReports,
		ReproducedFaultInjection: cached.FaultInjection,
	}, cached.CoverageID, nil
}

func ReproduceFunc(ctx *aflow.Context, args ReproduceArgs) (reproduceResult, error) {
	res, _, err := ReproduceFuncWithCoverage(ctx, args, false)
	return res, err
}

func symbolize(targetArch, kernelObj string, coverage [][]uint64) ([][]symbolizer.Frame, error) {
	pcs := make(map[uint64][]symbolizer.Frame)
	for _, call := range coverage {
		for _, pc := range call {
			pcs[pc] = nil
		}
	}
	target := targets.Get(targets.Linux, targetArch)
	vmlinux := filepath.Join(kernelObj, target.KernelObject)
	symb := symbolizer.Make(target)
	defer symb.Close()
	frames, err := symb.Symbolize(vmlinux, slices.Collect(maps.Keys(pcs))...)
	if err != nil {
		return nil, err
	}
	for _, frame := range frames {
		pcs[frame.PC] = append(pcs[frame.PC], frame)
	}
	var res [][]symbolizer.Frame
	// TODO(dvyukov): figure out how we want to aggregate/deduplicate frames
	// We may leave only the last call. We also most likely want to handle
	// inline frames in some way. We may also want to deduplicate/aggregate
	// the full trace in some way.
	for _, call := range coverage {
		var frames []symbolizer.Frame
		for _, pc := range call {
			frames = append(frames, pcs[pc]...)
		}
		res = append(res, frames)
	}
	return res, nil
}
