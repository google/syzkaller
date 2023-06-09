// Copyright 2019 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vcs

import (
	"fmt"

	"github.com/google/syzkaller/pkg/debugtracer"
	"github.com/google/syzkaller/sys/targets"
)

type testos struct {
	*git
}

var (
	_ Bisecter        = new(testos)
	_ ConfigMinimizer = new(testos)
)

func newTestos(dir string, opts []RepoOpt) *testos {
	return &testos{
		git: newGit(dir, nil, opts),
	}
}

func (ctx *testos) PreviousReleaseTags(commit, compilerType string) ([]string, error) {
	return ctx.git.previousReleaseTags(commit, false, false, false)
}

func (ctx *testos) EnvForCommit(
	defaultCompiler, compilerType, binDir, commit string,
	kernelConfig []byte, dt debugtracer.DebugTracer,
) (*BisectEnv, error) {
	return &BisectEnv{KernelConfig: kernelConfig}, nil
}

func (ctx *testos) Minimize(target *targets.Target, original []byte, dt debugtracer.DebugTracer,
	pred func(test []byte) (BisectResult, error),
	how ...interface{},
) ([]byte, error) {
	for _, task := range how {
		baseline, ok := task.(*AgainstBaseline)
		if !ok {
			continue
		}
		if res, err := pred(baseline.Baseline); err != nil {
			return nil, err
		} else if res == BisectBad {
			return baseline.Baseline, nil
		}
		switch string(baseline.Baseline) {
		case "minimize-fails":
			return nil, fmt.Errorf("minimization failure")
		case "minimize-succeeds":
			config := []byte("new-minimized-config")
			pred(config)
			return config, nil
		default:
			return original, nil
		}
	}
	return original, nil
}

func (ctx *testos) PrepareBisect() error {
	return nil
}
