// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"sort"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/vcs"
)

func extractModifiedFiles(cfg *mgrconfig.Config, data []byte) {
	const maxAffectedByHeader = 50

	names := map[string]bool{}
	includedNames := map[string]bool{}
	for _, file := range vcs.ParseGitDiff(data) {
		names[file] = true

		if strings.HasSuffix(file, ".h") && cfg.KernelSrc != "" {
			// Ideally, we should combine this with the recompilation process - then we know
			// exactly which files were affected by the patch.
			out, err := osutil.RunCmd(time.Minute, cfg.KernelSrc, "/usr/bin/grep",
				"-rl", "--include", `*.c`, `<`+strings.TrimPrefix(file, "include/")+`>`)
			if err != nil {
				log.Logf(0, "failed to grep for the header usages: %v", err)
				continue
			}
			lines := strings.Split(string(out), "\n")
			if len(lines) >= maxAffectedByHeader {
				// It's too widespread. It won't help us focus on anything.
				log.Logf(0, "the header %q is included in too many files (%d)", file, len(lines))
				continue
			}
			for _, name := range lines {
				name = strings.TrimSpace(name)
				if name == "" {
					continue
				}
				includedNames[name] = true
			}
		}
	}

	var namesList, includedList []string
	for name := range names {
		namesList = append(namesList, name)
	}
	for name := range includedNames {
		if names[name] {
			continue
		}
		includedList = append(includedList, name)
	}

	if len(namesList) > 0 {
		sort.Strings(namesList)
		log.Logf(0, "adding the following modified files to focus_order: %q", namesList)
		cfg.Experimental.FocusAreas = append(cfg.Experimental.FocusAreas,
			mgrconfig.FocusArea{
				Name: "modified",
				Filter: mgrconfig.CovFilterCfg{
					Files: namesList,
				},
				Weight: 3.0,
			})
	}

	if len(includedList) > 0 {
		sort.Strings(includedList)
		log.Logf(0, "adding the following included files to focus_order: %q", includedList)
		cfg.Experimental.FocusAreas = append(cfg.Experimental.FocusAreas,
			mgrconfig.FocusArea{
				Name: "included",
				Filter: mgrconfig.CovFilterCfg{
					Files: includedList,
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
