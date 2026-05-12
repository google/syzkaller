// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package build

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/sys/targets"
)

type shell struct {
	script string
}

func (s shell) build(params Params) (ImageDetails, error) {
	return s.run(params, "build")
}

func (s shell) clean(params Params) error {
	_, err := s.run(params, "clean")
	return err
}

func (s shell) run(params Params, action string) (ImageDetails, error) {
	cmd := osutil.Command("sh", "-c", s.script)
	cmd.Dir = params.KernelDir
	cmd.Env = slices.Clone(os.Environ())
	cmd.Env = append(cmd.Env,
		"SYZ_TARGET_OS="+params.TargetOS,
		"SYZ_TARGET_ARCH="+params.TargetArch,
		"SYZ_VM_TYPE="+params.VMType,
		"SYZ_KERNEL_DIR="+params.KernelDir,
		"SYZ_OUTPUT_DIR="+params.OutputDir,
		"SYZ_COMPILER="+params.Compiler,
		"SYZ_LINKER="+params.Linker,
		"SYZ_CCACHE="+params.Ccache,
		"SYZ_USERSPACE_DIR="+params.UserspaceDir,
		"SYZ_CMDLINE_FILE="+params.CmdlineFile,
		"SYZ_SYSCTL_FILE="+params.SysctlFile,
		"SYZ_BUILD_CPUS="+fmt.Sprint(params.BuildCPUs),
		"SYZ_BUILD_ACTION="+action,
	)
	if _, err := osutil.Run(2*time.Hour, cmd); err != nil {
		return ImageDetails{}, fmt.Errorf("%v", osutil.VerboseMessage(err))
	}
	if action == "clean" {
		return ImageDetails{}, nil
	}
	sysTarget := targets.Get(params.TargetOS, params.TargetArch)
	required := []string{"image", filepath.Join("obj", sysTarget.KernelObject)}
	for _, file := range required {
		if !osutil.IsExist(filepath.Join(params.OutputDir, file)) {
			return ImageDetails{}, fmt.Errorf("build did not produce required file %v", file)
		}
	}
	sig, err := elfBinarySignature(filepath.Join(params.OutputDir, "obj", sysTarget.KernelObject), params.Tracer)
	if err != nil {
		return ImageDetails{}, err
	}
	return ImageDetails{Signature: sig}, err
}
