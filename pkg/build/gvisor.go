// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package build

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/osutil"
)

type gvisor struct{}

func (gvisor gvisor) build(targetArch, vmType, kernelDir, outputDir, compiler, userspaceDir,
	cmdlineFile, sysctlFile string, config []byte) error {
	args := []string{"build", "--verbose_failures"}
	if strings.Contains(" "+string(config)+" ", " -race ") {
		args = append(args, "--features=race")
	}
	args = append(args, "runsc")
	if _, err := osutil.RunCmd(20*time.Minute, kernelDir, compiler, args...); err != nil {
		return err
	}
	if err := gvisor.copyBinary(kernelDir, outputDir); err != nil {
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

func (gvisor) copyBinary(kernelDir, outputDir string) error {
	// Funny it's not possible to understand what bazel actually built...
	for _, typ := range []string{
		"linux_amd64_pure_stripped",
		"linux_amd64_static_stripped",
		"linux_amd64_static_race_stripped",
	} {
		runsc := filepath.Join(kernelDir, "bazel-bin", "runsc", typ, "runsc")
		if !osutil.IsExist(runsc) {
			continue
		}
		return osutil.CopyFile(runsc, filepath.Join(outputDir, "image"))
	}
	return fmt.Errorf("failed to locate bazel output")
}

func (gvisor) clean(kernelDir string) error {
	// Let's assume that bazel always properly handles build without cleaning (until proven otherwise).
	return nil
}
