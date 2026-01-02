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
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/sys/targets"
)

// Reproduce action tries to reproduce a crash with the given reproducer,
// and outputs the resulting crash report.
// If the reproducer does not trigger a crash, action fails.
var Reproduce = aflow.NewFuncAction("crash-reproducer", reproduce)

type reproduceArgs struct {
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
	CrashReport string
}

func reproduce(ctx *aflow.Context, args reproduceArgs) (reproduceResult, error) {
	if args.Type != "qemu" {
		// Since we use injected kernel boot, and don't build full disk image.
		return reproduceResult{}, errors.New("only qemu VM type is supported")
	}
	imageData, err := os.ReadFile(args.Image)
	if err != nil {
		return reproduceResult{}, err
	}
	desc := fmt.Sprintf("kernel commit %v, kernel config hash %v, image hash %v,"+
		" vm %v, vm config hash %v, C repro hash %v",
		args.KernelCommit, hash.String(args.KernelConfig), hash.String(imageData),
		args.Type, hash.String(args.VM), hash.String(args.ReproC))
	dir, err := ctx.Cache("repro", desc, func(dir string) error {
		var vmConfig map[string]any
		if err := json.Unmarshal(args.VM, &vmConfig); err != nil {
			return fmt.Errorf("failed to parse VM config: %w", err)
		}
		vmConfig["kernel"] = filepath.Join(args.KernelObj, filepath.FromSlash(build.LinuxKernelImage(targets.AMD64)))
		vmCfg, err := json.Marshal(vmConfig)
		if err != nil {
			return fmt.Errorf("failed to serialize VM config: %w", err)
		}
		cfg := mgrconfig.DefaultValues()
		cfg.RawTarget = "linux/amd64"
		cfg.Workdir = filepath.Join(dir, "workdir")
		cfg.Syzkaller = args.Syzkaller
		cfg.KernelObj = args.KernelObj
		cfg.KernelSrc = args.KernelSrc
		cfg.Image = args.Image
		cfg.Type = args.Type
		cfg.VM = vmCfg
		if err := mgrconfig.SetTargets(cfg); err != nil {
			return err
		}
		if err := mgrconfig.Complete(cfg); err != nil {
			return err
		}
		env, err := instance.NewEnv(cfg, nil, nil)
		if err != nil {
			return err
		}
		results, err := env.Test(1, nil, nil, []byte(args.ReproC))
		if err != nil {
			return err
		}
		os.RemoveAll(cfg.Workdir)
		if results[0].Error == nil {
			results[0].Error = errors.New("reproducer did not crash")
		}
		file, data := "", []byte(nil)
		var crashErr *instance.CrashError
		if errors.As(results[0].Error, &crashErr) {
			file, data = "report", crashErr.Report.Report
		} else {
			file, data = "error", []byte(results[0].Error.Error())
		}
		return osutil.WriteFile(filepath.Join(dir, file), data)
	})
	if err != nil {
		return reproduceResult{}, err
	}
	if data, err := os.ReadFile(filepath.Join(dir, "error")); err == nil {
		return reproduceResult{}, errors.New(string(data))
	}
	data, err := os.ReadFile(filepath.Join(dir, "report"))
	return reproduceResult{
		CrashReport: string(data),
	}, err
}
