// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package build

import (
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/sys/targets"
)

type gvisor struct{}

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
	bazelOpts := "--verbose_failures"

	target := "//runsc:runsc"
	if config.Coverage {
		if config.Race {
			target = "//runsc:runsc_race_coverage"
		} else {
			target = "//runsc:runsc_coverage"
		}
	} else if config.Race {
		bazelOpts += " --config=race "
		target = "//runsc:runsc-race"
	}

	outBinary := filepath.Join(params.OutputDir, "image")
	cmd := osutil.Command("make", "copy",
		"DOCKER_BUILD=0",
		fmt.Sprintf("BAZEL_OPTIONS=%s", bazelOpts),
		fmt.Sprintf("TARGETS=%s", target),
		fmt.Sprintf("DESTINATION=%s", outBinary),
	)
	cmd.Dir = params.KernelDir

	log.Logf(0, "bazel copy: %v", cmd.Env)
	if _, err := osutil.Run(60*time.Minute, cmd); err != nil {
		return ImageDetails{}, err
	}

	sysTarget := targets.Get(params.TargetOS, params.TargetArch)
	return ImageDetails{}, osutil.CopyFile(outBinary, filepath.Join(params.OutputDir, "obj", sysTarget.KernelObject))
}

func (gvisor) clean(params Params) error {
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
