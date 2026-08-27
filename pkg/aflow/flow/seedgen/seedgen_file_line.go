// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package seedgen

import (
	"encoding/json"
	"fmt"
	"path/filepath"

	"github.com/google/syzkaller/docs"
	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/action/crash"
	"github.com/google/syzkaller/pkg/aflow/action/kernel"
	"github.com/google/syzkaller/pkg/aflow/ai"
	"github.com/google/syzkaller/pkg/cover/backend"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/vminfo"
	"github.com/google/syzkaller/sys/targets"
)

type SeedGenFileLineInputs struct {
	AgentName     string
	FilePath      string
	LineNumber    int
	KernelRepo    string
	KernelCommit  string
	KernelConfig  string
	Image         string
	Type          string
	VM            json.RawMessage
	CorpusVMCount int
	Syzkaller     string
	TargetOS      string
	TargetArch    string
	CorpusPath    string
	Snapshot      bool
}

func init() {
	aflow.Register[SeedGenFileLineInputs, ai.SeedGenOutputs](
		ai.WorkflowSeedGenFileLine,
		"generate a syzlang program to reach a specific file path and line number",
		&aflow.Flow{
			Consts: map[string]any{
				"DocProgramSyntax":             docs.ProgramSyntax,
				"DocSyscallDescriptionsSyntax": docs.SyscallDescriptionsSyntax,
				"DocPseudoSyscalls":            docs.PseudoSyscalls,
				"DocSyzOS":                     docs.SyzOS,
			},
			Root: seedGenPipeline(
				kernel.Checkout,
				kernel.Build,
				crash.ActionConfigureRunner,
				ActionResolveLineToPC,
			),
		},
	)
}

type ResolveLineToPCArgs struct {
	FilePath   string
	LineNumber int
	KernelSrc  string
	KernelObj  string
}

type ResolveLineToPCResult struct {
	PCs []string `jsonschema:"Candidate KCOV PCs for file and line (hex), with PCs[0] as primary."`
}

var ActionResolveLineToPC = aflow.NewFuncAction("resolve-line-to-pc", resolveLineToPCAction)

func resolveLineToPCAction(ctx *aflow.Context, args ResolveLineToPCArgs) (ResolveLineToPCResult, error) {
	if args.FilePath == "" || args.LineNumber <= 0 {
		return ResolveLineToPCResult{}, fmt.Errorf("both FilePath and LineNumber must be provided")
	}

	pcs, err := resolveLineToPCs(args.KernelSrc, args.KernelObj, args.FilePath, args.LineNumber)
	if err != nil {
		return ResolveLineToPCResult{}, err
	}

	hexPCs := make([]string, len(pcs))
	for i, pc := range pcs {
		hexPCs[i] = fmt.Sprintf("0x%x", pc)
	}

	return ResolveLineToPCResult{
		PCs: hexPCs,
	}, nil
}

func resolveLineToPCs(kernelSrc, kernelObj, filePath string, line int) ([]uint64, error) {
	target := targets.Get(targets.Linux, targets.AMD64)
	vmlinux := filepath.Join(kernelObj, target.KernelObject)

	cfg := &mgrconfig.Config{
		KernelObj: kernelObj,
		KernelSrc: kernelSrc,
	}
	cfg.SysTarget = target
	modules := []*vminfo.KernelModule{
		{Path: vmlinux},
	}

	impl, err := backend.Make(cfg, modules)
	if err != nil {
		return nil, fmt.Errorf("failed to build coverage backend: %w", err)
	}

	return impl.ResolveLineToPCs(filePath, line)
}
