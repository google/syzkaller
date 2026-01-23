// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package diff

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/vcs"
)

const (
	symbolsArea  = "symbols"
	filesArea    = "files"
	includesArea = "included"
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

	direct, transitive := affectedFiles(cfg, gitPatches)
	if len(direct) > 0 {
		sort.Strings(direct)
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

	if len(transitive) > 0 {
		sort.Strings(transitive)
		log.Logf(0, "adding transitively affected to focus areas: %q", transitive)
		cfg.Experimental.FocusAreas = append(cfg.Experimental.FocusAreas,
			mgrconfig.FocusArea{
				Name: includesArea,
				Filter: mgrconfig.CovFilterCfg{
					Files: transitive,
				},
				Weight: 2.0,
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

func affectedFiles(cfg *mgrconfig.Config, gitPatches [][]byte) (direct, transitive []string) {
	const maxAffectedByHeader = 50

	directMap := make(map[string]struct{})
	transitiveMap := make(map[string]struct{})
	var allFiles []string
	for _, patch := range gitPatches {
		for _, diff := range vcs.ParseGitDiff(patch) {
			allFiles = append(allFiles, diff.Name)
		}
	}
	for _, file := range allFiles {
		directMap[file] = struct{}{}
		if !strings.HasSuffix(file, ".h") || cfg.KernelSrc == "" {
			continue
		}
		// For .h files, we want to determine all the .c files that include them.
		// Ideally, we should combine this with the recompilation process - then we know
		// exactly which files were affected by the patch.
		matching, err := osutil.GrepFiles(cfg.KernelSrc, `.c`,
			[]byte(`<`+strings.TrimPrefix(file, "include/")+`>`))
		if err != nil {
			log.Logf(0, "failed to grep for includes: %s", err)
			continue
		}
		if len(matching) >= maxAffectedByHeader {
			// It's too widespread. It won't help us focus on anything.
			log.Logf(0, "the header %q is included in too many files (%d)", file, len(matching))
			continue
		}
		for _, name := range matching {
			transitiveMap[name] = struct{}{}
		}
	}
	for name := range directMap {
		direct = append(direct, name)
	}
	for name := range transitiveMap {
		if _, ok := directMap[name]; ok {
			continue
		}
		transitive = append(transitive, name)
	}
	return
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
	sort.Strings(ret)
	return ret
}
