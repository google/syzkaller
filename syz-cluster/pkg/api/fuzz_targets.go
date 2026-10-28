// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package api

import (
	_ "embed"
	"fmt"

	"gopkg.in/yaml.v3"
)

//go:embed fuzz_targets.yaml
var defaultFuzzTargetsYAML []byte

// DefaultFuzzTargets returns the default rules that map patch series to fuzzing configurations.
// Every call returns a new copy, so the caller may modify the result.
func DefaultFuzzTargets() []*FuzzTriageTarget {
	var targets []*FuzzTriageTarget
	if err := yaml.Unmarshal(defaultFuzzTargetsYAML, &targets); err != nil {
		// The file is embedded and is checked by tests, so it must never happen.
		panic(fmt.Sprintf("invalid fuzz_targets.yaml: %v", err))
	}
	return targets
}
