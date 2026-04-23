// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package crash

import (
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
}

type reproduceResult struct {
	ReproducedBugTitle    string
	ReproducedCrashReport string
}

type RunTestResult struct {
	// Returned if the program caused a kernel crash.
	Report *report.Report
	// Returned if the kernel failed to boot or function properly
	// (Report is not returned in this case).
	BootError string
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
	vmConfig["kernel"] = filepath.Join(args.KernelObj, filepath.FromSlash(build.LinuxKernelImage(targets.AMD64)))
	vmCfg, err := json.Marshal(vmConfig)
	if err != nil {
		return res, fmt.Errorf("failed to serialize VM config: %w", err)
	}

	cfg := mgrconfig.DefaultValues()
	cfg.RawTarget = "linux/amd64"
	cfg.Workdir = workdir
	cfg.Syzkaller = args.Syzkaller
	cfg.KernelObj = args.KernelObj
	cfg.KernelSrc = args.KernelSrc
	cfg.Image = args.Image
	cfg.Type = args.Type
	cfg.VM = vmCfg
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
	// TODO: run multiple instances, handle TestError.Infra, and aggregate results.
	results, err := env.Test(1, []byte(args.ReproSyz), []byte(args.ReproOpts), []byte(args.ReproC), collectCoverage)
	if err != nil {
		return res, err
	}
	if len(results) == 0 {
		return res, fmt.Errorf("env.Test returned no results")
	}
	res.ConsoleOutput = string(results[0].RawOutput)
	if err := results[0].Error; err != nil {
		if crashErr := new(instance.CrashError); errors.As(err, &crashErr) {
			res.Report = crashErr.Report
		} else if testErr := new(instance.TestError); errors.As(err, &testErr) {
			if testErr.Infra {
				// No point in showing this to LLM and asking to fix.
				return res, fmt.Errorf("%v\n%v\n%s",
					testErr.Error(), testErr.Title, testErr.Output)
			}
			res.BootError = parseTestError(testErr)
		} else {
			res.BootError = err.Error()
		}
	}
	coverage, err := symbolize(args.KernelObj, results[0].Coverage)
	if err != nil {
		return res, fmt.Errorf("failed to symbolize coverage: %w", err)
	}
	res.Coverage = coverage
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
		" vm %v, vm config hash %v, C repro hash %v, syz repro hash %v, opts hash %v, cov %v, version 5",
		args.KernelCommit, hash.String(args.KernelConfig), hash.String(imageData),
		args.Type, hash.String(args.VM), hash.String(args.ReproC),
		hash.String(args.ReproSyz), hash.String(args.ReproOpts), collectCoverage)
	type Cached struct {
		BugTitle   string
		Report     string
		Error      string
		CoverageID string
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
	} else if cached.Report == "" {
		return reproduceResult{}, cached.CoverageID, aflow.FlowError(ErrDidNotCrash)
	}
	return reproduceResult{
		ReproducedBugTitle:    cached.BugTitle,
		ReproducedCrashReport: cached.Report,
	}, cached.CoverageID, nil
}

func ReproduceFunc(ctx *aflow.Context, args ReproduceArgs) (reproduceResult, error) {
	res, _, err := ReproduceFuncWithCoverage(ctx, args, false)
	return res, err
}

func symbolize(kernelObj string, coverage [][]uint64) ([][]symbolizer.Frame, error) {
	pcs := make(map[uint64][]symbolizer.Frame)
	for _, call := range coverage {
		for _, pc := range call {
			pcs[pc] = nil
		}
	}
	target := targets.Get(targets.Linux, targets.AMD64)
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
