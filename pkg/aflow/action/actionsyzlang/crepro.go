// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// Package actionsyzlang provides actions for generating and formatting syzlang programs and C reproducers.
package actionsyzlang

import (
	"fmt"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/syzspec"
	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/report"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

var CreateSimplifiedCRepro = aflow.NewFuncAction("syz-repro-to-c-repro", createCRepro)

type createCReproArgs struct {
	TargetOS   string
	TargetArch string
	ReproSyz   string
	ReproC     string
}

type createCReproResult struct {
	SimplifiedCRepro string
}

func createCRepro(ctx *aflow.Context, args createCReproArgs) (createCReproResult, error) {
	if args.ReproSyz == "" {
		// Patching workflow may run only with C repro, if created manually (not from a syzbot bug).
		// For these cases return the provided C repro.
		return createCReproResult{SimplifiedCRepro: truncateLargeData(args.ReproC)}, nil
	}
	pt, err := prog.GetTarget(args.TargetOS, args.TargetArch)
	if err != nil {
		return createCReproResult{}, fmt.Errorf("failed to get target %s/%s: %w", args.TargetOS, args.TargetArch, err)
	}
	p, err := pt.Deserialize([]byte(args.ReproSyz), prog.NonStrict)
	if err != nil {
		// Old reproducers may not deserialize against current descriptions (e.g. disabled,
		// renamed, or removed syscalls). Fall back instead of failing the whole job.
		// TODO: build the syzkaller revision that generated the reproducer
		// and use its descriptions/prog2c to convert the program.
		ctx.Logf(0, "failed to deserialize syz repro, falling back: %v", err)
		return createCReproResult{SimplifiedCRepro: fallbackRepro(args.ReproC, args.ReproSyz)}, nil
	}
	cData, err := csource.WriteLLM(p)
	if err != nil {
		ctx.Logf(0, "failed to generate simplified C repro, falling back: %v", err)
		return createCReproResult{SimplifiedCRepro: fallbackRepro(args.ReproC, args.ReproSyz)}, nil
	}
	return createCReproResult{SimplifiedCRepro: truncateLargeData(string(cData))}, nil
}

const (
	maxStringLiteralSeqLen = 128
	maxFallbackReproSize   = 16 * 1024
)

func fallbackRepro(reproC, reproSyz string) string {
	if reproC != "" {
		return string(report.Truncate([]byte(truncateLargeData(reproC)), 0, maxFallbackReproSize))
	}
	return string(report.Truncate([]byte(truncateLargeData(reproSyz)), maxFallbackReproSize, 0))
}

func truncateLargeData(cRepro string) string {
	return syzspec.StringLiteralSeq.ReplaceAllStringFunc(cRepro, func(match string) string {
		if len(match) > maxStringLiteralSeqLen {
			return `"... [truncated large byte array] ..."`
		}
		return match
	})
}
