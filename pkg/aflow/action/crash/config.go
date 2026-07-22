// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package crash

import (
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/google/syzkaller/pkg/build"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/sys/targets"
)

// TargetConfig defines the configuration for building a target environment for
// running programs in a VM.
type TargetConfig struct {
	// Name identifying the agent instance.
	AgentName string
	// Target architecture of the kernel under test (e.g., "amd64", "arm64").
	TargetArch string
	// Directory path containing syzkaller host/target binaries.
	Syzkaller string
	// Path to the disk image file used by the VM.
	Image string
	// Virtual machine type (e.g., "qemu" or "gce").
	Type string
	// JSON-encoded VM-type-specific configurations.
	VM json.RawMessage
	// Directory path containing the kernel source tree.
	KernelSrc string
	// Directory path containing kernel build artifacts (such as vmlinux).
	KernelObj string
	// Git commit hash/revision of the kernel.
	KernelCommit string
	// Kernel build configuration (.config file content).
	KernelConfig string
	// Path to the host strace binary.
	StraceBin string
	// Whether to capture strace output during test execution.
	NeedStrace bool
	// Isolation sandbox type (e.g., "none", "namespace", "setuid", "android").
	Sandbox string
	// Whether to run VM in snapshot mode (only supported with qemu VM type).
	Snapshot bool
}

// Validate checks if the target configuration is valid.
func (args TargetConfig) Validate() error {
	if targets.Get(targets.Linux, args.TargetArch) == nil {
		return fmt.Errorf("unsupported target: %v/%v", targets.Linux, args.TargetArch)
	}
	switch args.Type {
	case vmQemu, "gce":
	default:
		return fmt.Errorf("unsupported VM type %q", args.Type)
	}
	switch args.Sandbox {
	case "", "none", "setuid", "namespace", "android":
	default:
		return fmt.Errorf("unsupported sandbox type %q", args.Sandbox)
	}
	return nil
}

func BuildConfig(args TargetConfig, workdir string) (*mgrconfig.Config, error) {
	var vmConfig map[string]any
	if len(args.VM) > 0 {
		if err := json.Unmarshal(args.VM, &vmConfig); err != nil {
			return nil, fmt.Errorf("failed to parse VM config: %w", err)
		}
	}
	if vmConfig == nil {
		vmConfig = make(map[string]any)
	}

	targetArch := args.TargetArch
	image := args.Image

	kernelPath := filepath.Join(args.KernelObj, filepath.FromSlash(build.LinuxKernelImage(targetArch)))
	switch args.Type {
	case vmQemu:
		vmConfig["kernel"] = kernelPath
	case "gce":
		params := build.Params{
			TargetOS:     targets.Linux,
			TargetArch:   targetArch,
			UserspaceDir: image,
			OutputDir:    workdir,
		}
		if err := build.EmbedLinuxKernel(params, kernelPath); err != nil {
			return nil, fmt.Errorf("failed to embed kernel into image: %w", err)
		}
		image = filepath.Join(workdir, "image")
	}

	vmCfg, err := json.Marshal(vmConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize VM config: %w", err)
	}

	cfg := mgrconfig.DefaultValues()
	cfg.Name = args.AgentName
	cfg.RawTarget = targets.Linux + "/" + targetArch
	cfg.Workdir = workdir
	cfg.Syzkaller = args.Syzkaller
	cfg.KernelObj = args.KernelObj
	cfg.KernelSrc = args.KernelSrc
	cfg.Image = image
	cfg.Type = args.Type
	cfg.VM = vmCfg
	if args.Sandbox != "" {
		cfg.Sandbox = args.Sandbox
	}
	if args.Snapshot && args.Type != vmQemu {
		return nil, fmt.Errorf("snapshot mode is only supported with qemu VM type")
	}
	cfg.Snapshot = args.Snapshot
	cfg.Experimental.DescriptionsMode = mgrconfig.AnyDescriptionsMode
	if args.NeedStrace && args.StraceBin != "" {
		cfg.StraceBin = args.StraceBin
		cfg.StraceBinOnTarget = false
	}

	if err := mgrconfig.SetTargets(cfg); err != nil {
		return nil, err
	}
	if err := mgrconfig.Complete(cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}
