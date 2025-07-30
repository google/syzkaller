// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package triage

import (
	"strings"

	"github.com/google/syzkaller/syz-cluster/pkg/api"
)

func SelectFuzzConfig(series *api.Series, fuzzConfigs []*api.FuzzConfig) *api.FuzzConfig {
	seriesCc := map[string]bool{}
	for _, cc := range series.Cc {
		seriesCc[strings.ToLower(cc)] = true
	}
	for _, config := range fuzzConfigs {
		intersects := false
		for _, cc := range config.EmailLists {
			intersects = intersects || seriesCc[cc]
		}
		if len(config.EmailLists) != 0 && !intersects {
			continue
		}
		return config
	}
	return nil
}
