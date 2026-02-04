// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package crash

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/build"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/instance"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/sys/targets"
)

// Reproduce action tries to reproduce a crash with the given reproducer,
// and outputs the resulting crash report.
// If the reproducer does not trigger a crash, action fails.
var Reproduce = aflow.NewFuncAction("crash-reproducer", reproduce)

type ReproduceArgs struct {
	Syzkaller       string
	Image           string
	Type            string
	VM              json.RawMessage
	ReproOpts       string
	ReproSyz        string
	ReproC          string
	SyzkallerCommit string
	KernelSrc       string
	KernelObj       string
	KernelCommit    string
	KernelConfig    string
}

type reproduceResult struct {
	BugTitle    string
	CrashReport string
}

// ReproduceCrash tests reproducer and returns:
//   - Report: if the reproducer caused the kernel crash
//   - boot failure: if the kernel failed to boot or function properly
//     (if kernel crashed during build/boot, the Report is not returned)
//   - error: for unexpected failures
//
// All 3 values are empty, if everything went well, and kernel has not crashed.
func ReproduceCrash(args ReproduceArgs, workdir string) (*report.Report, string, error) {
	if args.Type != "qemu" {
		return nil, "", errors.New("only qemu VM type is supported")
	}

	var vmConfig map[string]any
	if err := json.Unmarshal(args.VM, &vmConfig); err != nil {
		return nil, "", fmt.Errorf("failed to parse VM config: %w", err)
	}
	vmConfig["kernel"] = filepath.Join(args.KernelObj, filepath.FromSlash(build.LinuxKernelImage(targets.AMD64)))
	vmCfg, err := json.Marshal(vmConfig)
	if err != nil {
		return nil, "", fmt.Errorf("failed to serialize VM config: %w", err)
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
		return nil, "", err
	}
	if err := mgrconfig.Complete(cfg); err != nil {
		return nil, "", err
	}
	env, err := instance.NewEnv(cfg, nil, nil)
	if err != nil {
		return nil, "", err
	}
	// TODO: run multiple instances, handle TestError.Infra, and aggregate results.
	results, err := env.Test(1, nil, nil, []byte(args.ReproC))
	if err != nil {
		return nil, "", err
	}
	if err := results[0].Error; err != nil {
		if crashErr := new(instance.CrashError); errors.As(err, &crashErr) {
			return crashErr.Report, "", nil
		} else if testErr := new(instance.TestError); errors.As(err, &testErr) {
			return parseTestError(testErr)
		} else {
			return nil, err.Error(), nil
		}
	}
	return nil, "", nil
}

func parseTestError(err *instance.TestError) (*report.Report, string, error) {
	if err.Infra {
		// No point in showing this to LLM and asking to fix.
		return nil, "", fmt.Errorf("%v\n%v\n%s", err.Error(), err.Title, err.Output)
	}
	what := "Basic kernel testing failed"
	if err.Boot {
		what = "Kernel failed to boot"
	}
	extraInfo := err.Output
	// Don't use TestError.Report for crashes like "lost connection" that don't have a report.
	if err.Report != nil && err.Report.Report != nil {
		extraInfo = err.Report.Report
	}
	return nil, fmt.Sprintf("%v: %v\n%s", what, err.Title, extraInfo), nil
}

func reproduce(ctx *aflow.Context, args ReproduceArgs) (reproduceResult, error) {
	imageData, err := os.ReadFile(args.Image)
	if err != nil {
		return reproduceResult{}, err
	}
	desc := fmt.Sprintf("kernel commit %v, kernel config hash %v, image hash %v,"+
		" vm %v, vm config hash %v, C repro hash %v, version 3",
		args.KernelCommit, hash.String(args.KernelConfig), hash.String(imageData),
		args.Type, hash.String(args.VM), hash.String(args.ReproC))
	type Cached struct {
		BugTitle string
		Report   string
		Error    string
	}
	cached, err := aflow.CacheObject(ctx, "repro", desc, func() (Cached, error) {
		var res Cached
		workdir, err := ctx.TempDir()
		if err != nil {
			return res, err
		}
		rep, bootError, err := ReproduceCrash(args, workdir)
		if rep != nil {
			res.BugTitle = rep.Title
			res.Report = string(rep.Report)
		}
		res.Error = bootError
		return res, err
	})
	if err != nil {
		return reproduceResult{}, err
	}
	if cached.Error != "" {
		return reproduceResult{}, errors.New(cached.Error)
	} else if cached.Report == "" {
		return reproduceResult{}, aflow.FlowError(errors.New("reproducer did not crash"))
	}
	return reproduceResult{
		BugTitle:    cached.BugTitle,
		CrashReport: cached.Report,
	}, nil
}
