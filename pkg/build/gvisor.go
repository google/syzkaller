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

	image := filepath.Join(params.OutputDir, "image")
	cmd := osutil.Command("make", "copy",
		"DOCKER_BUILD=0",
		"BAZEL_OPTIONS=--verbose_failures",
		fmt.Sprintf("TARGETS=%s", config.releaseTarget()),
		fmt.Sprintf("DESTINATION=%s", image),
	)
	cmd.Dir = params.KernelDir
	log.Logf(0, "bazel copy: %v", cmd.Args)
	_, err = osutil.Run(60*time.Minute, cmd)
	return ImageDetails{}, err
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

// releaseTarget returns the bazel target of the gVisor release tarball for the configuration.
func (cfg gvisorConfig) releaseTarget() string {
	switch {
	case cfg.Coverage && cfg.Race:
		return "//debian:gvisor-release-race-coverage-tar-bz2"
	case cfg.Coverage:
		return "//debian:gvisor-release-coverage-tar-bz2"
	case cfg.Race:
		return "//debian:gvisor-release-race-tar-bz2"
	default:
		return "//debian:gvisor-release-tar-bz2"
	}
}

// parseGVisorConfig parses a set of flags into a `gvisorConfig`.
func parseGVisorConfig(config []byte) (gvisorConfig, error) {
	var cfg gvisorConfig
	for flag := range strings.FieldsSeq(string(config)) {
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
