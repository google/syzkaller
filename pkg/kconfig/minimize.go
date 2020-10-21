// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package kconfig

import (
	"fmt"
	"io"
	"sort"
)

// Minimize finds an equivalent with respect to the provided predicate, but smaller config.
// It accepts base (small) and full (large) config. It is assumed that the predicate returns true for the full config.
// It is also assumed that base and full are not just two completely arbitrary configs, but full it produced from base
// mostly by adding more configs. The minimization procedure thus consists of figuring out what set of configs that
// are present in full and are not present in base affect the predicate.
func (kconf *KConfig) Minimize(base, full *ConfigFile, pred func(*ConfigFile) (bool, error),
	tw io.Writer) (*ConfigFile, error) {
	trace := traceLogger{tw}
	diff, other := kconf.missingConfigs(base, full)
	trace.log("kconfig minimization: base=%v full=%v diff=%v", len(base.Configs), len(full.Configs), len(diff))
	// First, check the base config as is, it is the smallest we can possibly get.
	if res, err := pred(base); err != nil {
		return nil, err
	} else if res {
		trace.log("base config crashes")
		return base, nil
	}
	// Since base does not crash, full config is our best bet for now.
	current := full.clone()
	var suspects map[string]bool
	// Take half of the diff between base and full, apply to base and test.
	// If this candidate config crashes, we commit it as new full and repeat the process.
	// If it does not crash, try another half.
	// If the crash is caused by a single config, this algorithm is guaranteed to find it.
	// If the crash is caused by multiple configs, this algorithm will most likely find them (along with some
	// additional unrelated configs that happened to be in the same half). However, amount of unrelated configs
	// can be quite large if we are unlucky. Also note that we sort configs so that related configs are most
	// likely situated together.
	// Numerous improvements are possible for this simple algorithm.
	// 1. We could split the config onto 4 parts and try all pairs, this should find all pairs of configs reliably.
	// 2. We could continue trying to reduce a part even if removing the whole part fails. I.e. we try to remove
	//    a half and it fails, we can try to remove half of the half, maybe that will succeed.
top:
	for len(diff) >= 2 {
		half := len(diff) / 2
		for _, part := range [][]string{diff[:half], diff[half:]} {
			trace.log("trying half: %v", part)
			closure := kconf.addDependencies(base, full, part)
			candidate := base.clone()
			// 1. Always move all non-tristate configs from full to base as we don't minimize them.
			for _, cfg := range other {
				candidate.Set(cfg.Name, cfg.Value)
			}
			for cfg := range closure {
				candidate.Set(cfg, Yes)
			}
			res, err := pred(candidate)
			if err != nil {
				return nil, err
			}
			if res {
				trace.log("half crashed")
				diff = part
				current = candidate
				suspects = closure
				continue top
			}
		}
		trace.log("both halves did not crash")
		break
	}
	if suspects != nil {
		trace.log("resulting configs: %v", suspects)
	} else {
		trace.log("only full config crashes")
	}
	return current, nil
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

func (kconf *KConfig) addDependencies(base, full *ConfigFile, configs []string) map[string]bool {
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
	return closure
}

type traceLogger struct{ io.Writer }

func (trace traceLogger) log(msg string, args ...interface{}) {
	if trace.Writer != nil {
		fmt.Fprintf(trace.Writer, msg+"\n", args...)
	}
}
