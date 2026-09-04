// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package fuzzing

import (
	"fmt"
	"slices"
	"strings"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/ai"
)

var ToolSeriesPatches = aflow.NewFuncTool("series-patches", seriesPatches, `
Tool allows exploring the original patch series submitted for testing.
Omit PatchNum to return the complete numbered list of all patch titles in the series.
Provide PatchNum (0 for cover letter, 1..N for patches) to view full description and diff.
`)

type seriesPatchesState struct {
	Patches []ai.SeriesPatch
}

type seriesPatchesArgs struct {
	PatchNum *int `jsonschema:"Patch sequence number (0 for cover). Omit to list."`
}

type seriesPatchesResult struct {
	Output string `jsonschema:"Formatted patch list or content of the selected patch."`
}

const maxPatchLines = 1000

func seriesPatches(ctx *aflow.Context, state seriesPatchesState, args seriesPatchesArgs) (seriesPatchesResult, error) {
	if len(state.Patches) == 0 {
		return seriesPatchesResult{Output: "No patches available in the series."}, nil
	}

	if args.PatchNum == nil {
		return seriesPatchesResult{Output: formatPatchList(state.Patches)}, nil
	}

	targetNum := *args.PatchNum
	var target *ai.SeriesPatch
	if idx := slices.IndexFunc(state.Patches, func(p ai.SeriesPatch) bool {
		return p.Seq == targetNum
	}); idx >= 0 {
		target = &state.Patches[idx]
	}

	if target == nil {
		list := formatPatchList(state.Patches)
		return seriesPatchesResult{
			Output: fmt.Sprintf("%s\n\n(Note: PatchNum %d was not found, showing full patch list above)",
				list, targetNum),
		}, nil
	}

	lines := slices.Collect(strings.Lines(target.Body))
	var body string
	if len(lines) > maxPatchLines {
		body = fmt.Sprintf("%s\n[Output truncated: showing %d of %d lines]",
			strings.TrimRight(strings.Join(lines[:maxPatchLines], ""), "\n"), maxPatchLines, len(lines))
	} else {
		body = target.Body
	}

	var output string
	if target.Seq == 0 {
		output = fmt.Sprintf("Cover letter [0] %s:\n\n%s\n\n%s", target.Title, body, formatPatchList(state.Patches))
	} else {
		output = fmt.Sprintf("Patch [%d] %s:\n\n%s", target.Seq, target.Title, body)
	}

	return seriesPatchesResult{
		Output: strings.TrimSpace(output),
	}, nil
}

func formatPatchList(patches []ai.SeriesPatch) string {
	var b strings.Builder
	fmt.Fprintf(&b, "The patch series contains %d patches:\n", len(patches))
	for _, p := range patches {
		if p.Seq == 0 {
			fmt.Fprintf(&b, "[0] (Cover letter) %s\n", p.Title)
		} else {
			fmt.Fprintf(&b, "[%d] %s\n", p.Seq, p.Title)
		}
	}
	return strings.TrimSpace(b.String())
}
