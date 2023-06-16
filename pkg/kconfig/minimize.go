// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package kconfig

import (
	"fmt"
	"sort"

	"github.com/google/syzkaller/pkg/bisect/minimize"
	"github.com/google/syzkaller/pkg/debugtracer"
)

// Minimize finds an equivalent with respect to the provided predicate, but smaller config.
// It accepts base (small) and full (large) config. It is assumed that the predicate returns true for the full config.
// It is also assumed that base and full are not just two completely arbitrary configs, but full it produced from base
// mostly by adding more configs. The minimization procedure thus consists of figuring out what set of configs that
// are present in full and are not present in base affect the predicate.
// If maxPredRuns is non-zero, minimization will stop after the specified number of runs.
func (kconf *KConfig) Minimize(base, full *ConfigFile, pred func(*ConfigFile) (bool, error),
	maxSteps int, dt debugtracer.DebugTracer) (*ConfigFile, error) {
	diff, other := kconf.missingLeafConfigs(base, full)
	dt.Log("kconfig minimization: base=%v full=%v leaves diff=%v", len(base.Configs), len(full.Configs), len(diff))

	diffToConfig := func(part []string) (*ConfigFile, []string) {
		if len(part) == 0 {
			// We're testing the baseline config only.
			return base, nil
		}
		suspects := kconf.addDependencies(base, full, part)
		candidate := base.Clone()
		// Always move all non-tristate configs from full to base as we don't minimize them.
		for _, cfg := range other {
			candidate.Set(cfg.Name, cfg.Value)
		}
		for _, cfg := range suspects {
			candidate.Set(cfg, Yes)
		}
		return candidate, suspects
	}
	var step int
	minimizePred := func(diffs []string) (bool, error) {
		step++
		config, _ := diffToConfig(diffs)
		dt.SaveFile(fmt.Sprintf("step_%d.config", step), config.Serialize())
		return pred(config)
	}
	result, err := minimize.Slice(
		minimize.Config[string]{
			Pred:     minimizePred,
			MaxSteps: maxSteps,
			Logf:     dt.Log,
		},
		diff,
	)
	if err != nil {
		return nil, err
	}
	config, suspects := diffToConfig(result)
	if suspects != nil {
		dt.Log("minimized to %d configs; suspects: %v", len(result), suspects)
		kconf.writeSuspects(dt, suspects)
	}
	return config, nil
}

func (kconf *KConfig) missingConfigs(base, full *ConfigFile) (tristate []string, other []*Config) {
	for _, cfg := range full.Configs {
		if cfg.Value == Yes && base.Value(cfg.Name) == No {
			tristate = append(tristate, cfg.Name)
		} else if cfg.Value != No && cfg.Value != Yes && cfg.Value != Mod {
			other = append(other, cfg)
		}
	}
	sort.Strings(tristate)
	return
}

// missingLeafConfigs returns the set of configs no other config depends upon.
func (kconf *KConfig) missingLeafConfigs(base, full *ConfigFile) ([]string, []*Config) {
	diff, other := kconf.missingConfigs(base, full)
	needed := map[string]bool{}
	for _, config := range diff {
		for _, needs := range kconf.addDependencies(base, full, []string{config}) {
			if needs != config {
				needed[needs] = true
			}
		}
	}
	var leaves []string
	for _, key := range diff {
		if !needed[key] {
			leaves = append(leaves, key)
		}
	}
	return leaves, other
}

func (kconf *KConfig) addDependencies(base, full *ConfigFile, configs []string) []string {
	closure := make(map[string]bool)
	for _, cfg := range configs {
		closure[cfg] = true
		if m := kconf.Configs[cfg]; m != nil {
			for dep := range m.DependsOn() {
				if full.Value(dep) != No && base.Value(dep) == No {
					closure[dep] = true
				}
			}
		}
	}
	var sorted []string
	for cfg := range closure {
		sorted = append(sorted, cfg)
	}
	sort.Strings(sorted)
	return sorted
}

const CauseConfigFile = "cause.config"

func (kconf *KConfig) writeSuspects(dt debugtracer.DebugTracer, suspects []string) {
	cf := &ConfigFile{
		Map: make(map[string]*Config),
	}
	for _, cfg := range suspects {
		cf.Set(cfg, Yes)
	}
	dt.SaveFile(CauseConfigFile, cf.Serialize())
}
