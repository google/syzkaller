// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package diff

import (
	"fmt"
	"maps"
	"regexp"
	"slices"

	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/vcs"
)

const (
	symbolsArea = "symbols"
	filesArea   = "files"
)

func PatchFocusAreas(cfg *mgrconfig.Config, gitPatches [][]byte, baseHashes, patchedHashes map[string]string) {
	funcs := modifiedSymbols(baseHashes, patchedHashes)
	if len(funcs) > 0 {
		log.Logf(0, "adding modified_functions to focus areas: %q", funcs)
		var regexps []string
		for _, name := range funcs {
			regexps = append(regexps, fmt.Sprintf("^%s$", regexp.QuoteMeta(name)))
		}
		cfg.Experimental.FocusAreas = append(cfg.Experimental.FocusAreas,
			mgrconfig.FocusArea{
				Name: symbolsArea,
				Filter: mgrconfig.CovFilterCfg{
					Functions: regexps,
				},
				Weight: 6.0,
			})
	}

	direct := affectedFiles(gitPatches)
	if len(direct) > 0 {
		log.Logf(0, "adding directly modified files to focus areas: %q", direct)
		cfg.Experimental.FocusAreas = append(cfg.Experimental.FocusAreas,
			mgrconfig.FocusArea{
				Name: filesArea,
				Filter: mgrconfig.CovFilterCfg{
					Files: direct,
				},
				Weight: 3.0,
			})
	}

	// Still fuzz the rest of the kernel.
	if len(cfg.Experimental.FocusAreas) > 0 {
		cfg.Experimental.FocusAreas = append(cfg.Experimental.FocusAreas,
			mgrconfig.FocusArea{
				Weight: 1.0,
			})
	}
}

func affectedFiles(gitPatches [][]byte) []string {
	directMap := make(map[string]struct{})
	for _, patch := range gitPatches {
		for _, diff := range vcs.ParseGitDiff(patch) {
			directMap[diff.Name] = struct{}{}
		}
	}
	return slices.Sorted(maps.Keys(directMap))
}

// If there are too many different symbols, they are no longer specific enough.
// Don't use them to focus the fuzzer.
const modifiedSymbolThreshold = 0.05

func modifiedSymbols(baseHashes, patchedHashes map[string]string) []string {
	var ret []string
	for name, hash := range patchedHashes {
		if baseHash, ok := baseHashes[name]; !ok || baseHash != hash {
			ret = append(ret, name)
			if float64(len(ret)) > float64(len(patchedHashes))*modifiedSymbolThreshold {
				return nil
			}
		}
	}
	slices.Sort(ret)
	return ret
}
