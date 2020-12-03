// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package build

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/osutil"
)

type gvisor struct{}

var bazelTargetPath = regexp.MustCompile(`(?sm:.*^)\s*Outputs: \[(.*)\](?sm:$.*)`)

func (gvisor gvisor) build(params *Params) error {
	// Bring down bazel daemon right away. We don't need it running and consuming memory.
	defer osutil.RunCmd(10*time.Minute, params.KernelDir, params.Compiler, "shutdown")

	config := strings.Fields(string(params.Config))
	args := []string{"build", "--verbose_failures"}
	target := "//runsc:runsc"
	if coverageEnabled(config) {
		args = append(args, []string{
			"--collect_code_coverage",
			"--instrumentation_filter=//pkg/...,-//pkg/sentry/platform/..."}...)
	}
	if raceEnabled(config) {
		args = append(args, "--features=race")
		target = "//runsc:runsc-race"
	}
	args = append(args, target)
	// The 1 hour timeout is quite high. But we've seen false positives with 20 mins
	// on the first build after bazel/deps update. Also other gvisor instances running
	// on the same machine contribute to longer build times.
	if _, err := osutil.RunCmd(60*time.Minute, params.KernelDir, params.Compiler, args...); err != nil {
		return err
	}

	// Find out a path to the runsc binary.
	out, err := osutil.RunCmd(time.Minute, params.KernelDir, params.Compiler,
		"aquery", fmt.Sprintf("mnemonic(\"GoLink\", %s)", target))
	if err != nil {
		return err
	}

	match := bazelTargetPath.FindSubmatch(out)
	if match == nil {
		return fmt.Errorf("failed to find the runsc binary")
	}
	outBinary := string(match[1])
	outBinary = filepath.Join(params.KernelDir, filepath.FromSlash(outBinary))

	if err := osutil.CopyFile(outBinary, filepath.Join(params.OutputDir, "image")); err != nil {
		return err
	}
	return nil
}

func (gvisor) clean(kernelDir, targetArch string) error {
	// Let's assume that bazel always properly handles build without cleaning (until proven otherwise).
	return nil
}

func coverageEnabled(config []string) bool {
	for _, flag := range config {
		if flag == "-cover" {
			return true
		}
	}
	return false
}

func raceEnabled(config []string) bool {
	for _, flag := range config {
		if flag == "-race" {
			return true
		}
	}
	return false
}
