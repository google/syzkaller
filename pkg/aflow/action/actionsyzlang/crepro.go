// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package actionsyzlang

import (
	"fmt"
	"regexp"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

var CreateSimplifiedCRepro = aflow.NewFuncAction("syz-repro-to-c-repro", createCRepro)

type createCReproArgs struct {
	ReproSyz string
	ReproC   string
}

type createCReproResult struct {
	SimplifiedCRepro string
}

var stringLiteralSeq = regexp.MustCompile(`"(?:[^"\\]|\\.)*"(?:\s*"(?:[^"\\]|\\.)*")*`)

func createCRepro(ctx *aflow.Context, args createCReproArgs) (createCReproResult, error) {
	if args.ReproSyz == "" {
		// Patching workflow may run only with C repro, if created manually (not from a syzbot bug).
		// For these cases return the provided C repro.
		return createCReproResult{truncateLargeData(args.ReproC)}, nil
	}
	pt, err := prog.GetTarget("linux", "amd64")
	if err != nil {
		return createCReproResult{}, fmt.Errorf("failed to get target linux/amd64: %w", err)
	}
	p, err := pt.Deserialize([]byte(args.ReproSyz), prog.NonStrict)
	if err != nil {
		return createCReproResult{}, fmt.Errorf("failed to deserialize syz repro: %w", err)
	}
	cData, err := csource.WriteLLM(p)
	if err != nil {
		return createCReproResult{}, fmt.Errorf("failed to generate simplified C repro: %w", err)
	}
	return createCReproResult{SimplifiedCRepro: truncateLargeData(string(cData))}, nil
}

const maxStringLiteralSeqLen = 128

func truncateLargeData(cRepro string) string {
	return stringLiteralSeq.ReplaceAllStringFunc(cRepro, func(match string) string {
		if len(match) > maxStringLiteralSeqLen {
			return `"... [truncated large byte array] ..."`
		}
		return match
	})
}
