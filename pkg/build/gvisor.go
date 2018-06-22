// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package build

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/google/syzkaller/pkg/osutil"
)

type gvisor struct{}

func (gvisor) build(targetArch, vmType, kernelDir, outputDir, compiler, userspaceDir,
	cmdlineFile, sysctlFile string, config []byte) error {
	if err := osutil.MkdirAll(outputDir); err != nil {
		return err
	}
	if _, err := osutil.RunCmd(20*time.Minute, kernelDir, compiler, "build", "--verbose_failures", "runsc"); err != nil {
		return err
	}
	runsc := filepath.Join(kernelDir, "bazel-bin", "runsc", "linux_amd64_pure_stripped", "runsc")
	if err := osutil.CopyFile(runsc, filepath.Join(outputDir, "image")); err != nil {
		return err
	}
	if len(config) != 0 {
		if err := osutil.WriteFile(filepath.Join(outputDir, "kernel.config"), config); err != nil {
			return fmt.Errorf("failed to save kernel config: %v", err)
		}
	}
	osutil.RunCmd(10*time.Minute, kernelDir, compiler, "shutdown")
	return nil
}

func (gvisor) clean(kernelDir string) error {
	// Let's assume that bazel always properly handles build without cleaning (until proven otherwise).
	return nil
}
