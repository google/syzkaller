// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package kconfig

import (
	"fmt"
	"math/rand"

	"github.com/google/syzkaller/pkg/debugtracer"
)

// Reduce finds an equivalent smaller config with respect to the `pred` predicate.
// Unlike Minize, Reduce does not aim at finding the least config, but rather tries to do
// its best in no more than `steps`.
func (kconf *KConfig) Reduce(base, full *ConfigFile, pred func(*ConfigFile) (bool, error),
	steps int, r *rand.Rand, dt debugtracer.DebugTracer) (*ConfigFile, error) {
	// Let's only consider leaf configs -- those that are not automatically enabled by anyone else.
	diff, other := kconf.missingLeafConfigs(base, full)
	dt.Log("kconfig reduce: base=%v full=%v diff=%v", len(base.Configs), len(full.Configs), len(diff))

	take := 0.75 // at first, aim at taking 3/4 of diffs
	current := full.clone()
	// TODO: prioritize the deletion of leaf configs (i.e. those that don't affect anything else)?
	// Presumably they should have the least effect, yet there's a lot of them.
	for step := 1; step <= steps; step++ {
		totalClosure := kconf.addDependencies(base, full, diff)
		dt.Log("step %d: diff=%v closure=%d take=%.2f", step, len(diff), len(totalClosure), take)
		r.Shuffle(len(diff), func(i, j int) {
			diff[i], diff[j] = diff[j], diff[i]
		})
		// We can't just take e.g. diff[:len(diff)*take], because after
		// addDependencies there'll be many more resulting diffs.
		// So pick one by one until we have reached the target.
		var yes, tookDiff []string
		// TODO: consider using binary search here.
		for i := 1; i <= len(diff); i++ {
			closure := kconf.addDependencies(base, full, diff[:i])
			if len(closure) == len(totalClosure) {
				// We've enabled everything. That's not a split.
				break
			}
			tookDiff = diff[:i]
			yes = closure
			if float64(len(closure)) >= take*float64(len(totalClosure)) {
				// Already enough.
				break
			}
		}
		candidate := base.clone()
		for _, cfg := range other {
			candidate.Set(cfg.Name, cfg.Value)
		}
		for _, cfg := range yes {
			candidate.Set(cfg, Yes)
		}
		dt.SaveFile(fmt.Sprintf("step_%d.config", step), candidate.Serialize())
		res, err := pred(candidate)
		if err != nil {
			return nil, err
		}
		if res {
			diff = tookDiff
			current = candidate
		} else if len(tookDiff) == 0 {
			dt.Log("empty diff didn't crash, stopping")
			break
		} else {
			// There's a chance that there are simply too many necessary kernel
			// configs. Slowly increase the share we take each step.
			take = take + (1.0-take)/4
		}
	}
	return current, nil
}

// missingLeafConfigs returns the set of configs no other config depends on.
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
