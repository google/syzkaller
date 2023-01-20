// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package build

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/sys/targets"
)

type gvisor struct{}

var bazelTargetPath = regexp.MustCompile(`(?sm:.*^)\s*Outputs: \[(.*)\](?sm:$.*)`)

func (gvisor gvisor) build(params Params) (ImageDetails, error) {
	if params.Compiler == "" {
		params.Compiler = "bazel"
	}

	// Bring down bazel daemon right away. We don't need it running and consuming memory.
	defer osutil.RunCmd(10*time.Minute, params.KernelDir, params.Compiler, "shutdown")

	config, err := parseGVisorConfig(params.Config)
	if err != nil {
		return ImageDetails{}, fmt.Errorf("cannot parse gVisor configuration: %w", err)
	}
	args := []string{}

	target := "//runsc:runsc"
	if config.Race {
		args = append(args, "--@io_bazel_rules_go//go/config:race")
		target = "//runsc:runsc-race"
	}
	if config.Coverage {
		coverageFiles := "//pkg/..."
		exclusions := []string{
			"//pkg/sentry/platform", "//pkg/ring0", // Breaks kvm.
			"//pkg/coverage:coverage", // Too slow.
		}
		if config.Race {
			// These targets use go:norace, which is not
			// respected by coverage instrumentation. Race builds
			// will be instrumented with atomic coverage (using
			// sync/atomic.AddInt32), which will not work.
			exclusions = append(exclusions, []string{
				"//pkg/sleep:sleep",
				"//pkg/syncevent:syncevent",
			}...)
		}
		for _, f := range exclusions {
			coverageFiles += ",-" + f
		}
		args = append(args, []string{
			"--collect_code_coverage",
			"--instrumentation_filter=" + coverageFiles}...)
	}
	buildArgs := []string{"build", "--verbose_failures"}
	buildArgs = append(buildArgs, args...)
	buildArgs = append(buildArgs, target)
	log.Logf(0, "bazel: %v", buildArgs)
	// The 1 hour timeout is quite high. But we've seen false positives with 20 mins
	// on the first build after bazel/deps update. Also other gvisor instances running
	// on the same machine contribute to longer build times.
	if _, err := osutil.RunCmd(60*time.Minute, params.KernelDir, params.Compiler, buildArgs...); err != nil {
		return ImageDetails{}, err
	}

	// Find out a path to the runsc binary.
	aqueryArgs := append([]string{"aquery"}, args...)
	aqueryArgs = append(aqueryArgs, fmt.Sprintf("mnemonic(\"GoLink\", %s)", target))
	log.Logf(0, "bazel: %v", aqueryArgs)
	out, err := osutil.RunCmd(10*time.Minute, params.KernelDir, params.Compiler, aqueryArgs...)
	if err != nil {
		return ImageDetails{}, err
	}

	match := bazelTargetPath.FindSubmatch(out)
	if match == nil {
		return ImageDetails{}, fmt.Errorf("failed to find the runsc binary")
	}
	outBinary := filepath.Join(params.KernelDir, filepath.FromSlash(string(match[1])))

	if err := osutil.CopyFile(outBinary, filepath.Join(params.OutputDir, "image")); err != nil {
		return ImageDetails{}, err
	}
	sysTarget := targets.Get(params.TargetOS, params.TargetArch)
	return ImageDetails{}, osutil.CopyFile(outBinary, filepath.Join(params.OutputDir, "obj", sysTarget.KernelObject))
}

func (gvisor) clean(kernelDir, targetArch string) error {
	// Let's assume that bazel always properly handles build without cleaning (until proven otherwise).
	return nil
}

// Known gVisor configuration flags.
const (
	gvisorFlagCover = "-cover"
	gvisorFlagRace  = "-race"
)

// gvisorConfig is a gVisor configuration.
type gvisorConfig struct {
	// Coverage represents whether code coverage is enabled.
	Coverage bool

	// Race represents whether race condition detection is enabled.
	Race bool
}

// parseGVisorConfig parses a set of flags into a `gvisorConfig`.
func parseGVisorConfig(config []byte) (gvisorConfig, error) {
	var cfg gvisorConfig
	for _, flag := range strings.Fields(string(config)) {
		switch flag {
		case gvisorFlagCover:
			cfg.Coverage = true
		case gvisorFlagRace:
			cfg.Race = true
		default:
			return cfg, fmt.Errorf("unknown gVisor configuration flag: %q", flag)
		}
	}
	return cfg, nil
}
