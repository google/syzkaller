// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package build

import (
	"path/filepath"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/osutil"
)

type gvisor struct{}

func (gvisor gvisor) build(targetArch, vmType, kernelDir, outputDir, compiler, userspaceDir,
	cmdlineFile, sysctlFile string, config []byte) error {
	outBinary := ""
	args := []string{"build", "--verbose_failures"}
	if strings.Contains(" "+string(config)+" ", " -race ") {
		args = append(args, "--features=race", "//runsc:runsc-race")
		outBinary = "bazel-bin/runsc/linux_amd64_static_race_stripped/runsc-race"
	} else {
		args = append(args, "//runsc:runsc")
		outBinary = "bazel-bin/runsc/linux_amd64_pure_stripped/runsc"
	}
	outBinary = filepath.Join(kernelDir, filepath.FromSlash(outBinary))
	if _, err := osutil.RunCmd(20*time.Minute, kernelDir, compiler, args...); err != nil {
		return err
	}
	if err := osutil.CopyFile(outBinary, filepath.Join(outputDir, "image")); err != nil {
		return err
	}
	osutil.RunCmd(10*time.Minute, kernelDir, compiler, "shutdown")
	return nil
}

func (gvisor) clean(kernelDir string) error {
	// Let's assume that bazel always properly handles build without cleaning (until proven otherwise).
	return nil
}
