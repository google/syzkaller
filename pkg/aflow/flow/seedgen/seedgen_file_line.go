// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package seedgen

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/google/syzkaller/docs"
	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/action/crash"
	"github.com/google/syzkaller/pkg/aflow/action/kernel"
	"github.com/google/syzkaller/pkg/aflow/ai"
	"github.com/google/syzkaller/pkg/aflow/tool/syzlang"
	"github.com/google/syzkaller/pkg/cover/backend"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/symbolizer"
	"github.com/google/syzkaller/pkg/vminfo"
	"github.com/google/syzkaller/sys/targets"
)

type SeedGenFileLineInputs struct {
	FilePath     string
	LineNumber   int
	KernelRepo   string
	KernelCommit string
	KernelConfig string
	Image        string
	Type         string
	VM           json.RawMessage
	Syzkaller    string
	TargetOS     string
	TargetArch   string
	CorpusPath   string
	Snapshot     bool
}

func init() {
	aflow.Register[SeedGenFileLineInputs, ai.SeedGenOutputs](
		ai.WorkflowSeedGenFileLine,
		"generate a syzlang program to reach a specific file path and line number",
		&aflow.Flow{
			Consts: map[string]any{
				"DescriptionFilesPrompt":       syzlang.DescriptionFilesPrompt(targets.Linux),
				"DocProgramSyntax":             docs.ProgramSyntax,
				"DocSyscallDescriptionsSyntax": docs.SyscallDescriptionsSyntax,
				"DocPseudoSyscalls":            docs.PseudoSyscalls,
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
	PC uint64
}

var ActionResolveLineToPC = aflow.NewFuncAction("resolve-line-to-pc", resolveLineToPCAction)

func resolveLineToPCAction(ctx *aflow.Context, args ResolveLineToPCArgs) (ResolveLineToPCResult, error) {
	if args.FilePath == "" || args.LineNumber <= 0 {
		return ResolveLineToPCResult{}, fmt.Errorf("both FilePath and LineNumber must be provided")
	}

	pc, err := resolveLineToPC(args.KernelSrc, args.KernelObj, args.FilePath, args.LineNumber)
	if err != nil {
		return ResolveLineToPCResult{}, err
	}
	return ResolveLineToPCResult{PC: pc}, nil
}

func resolveLineToPC(kernelSrc, kernelObj, filePath string, line int) (uint64, error) {
	target := targets.Get(targets.Linux, targets.AMD64)
	vmlinux := filepath.Join(kernelObj, target.KernelObject)

	kernelDirs := &mgrconfig.KernelDirs{
		Src: kernelSrc,
		Obj: kernelObj,
	}
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
		return 0, fmt.Errorf("failed to build coverage backend: %w", err)
	}

	cleanTargetFile, _ := backend.CleanPath(filePath, kernelDirs, nil)
	if cleanTargetFile == "" {
		cleanTargetFile = filepath.Clean(filePath)
	}

	var targetUnit *backend.CompileUnit
	for _, unit := range impl.Units {
		if matchDwarfFile(unit.Path, cleanTargetFile, kernelDirs) {
			targetUnit = unit
			break
		}
	}
	if targetUnit == nil || len(targetUnit.PCs) == 0 {
		return 0, fmt.Errorf("file %q not found or has no KCOV coverage points", filePath)
	}

	symb := symbolizer.Make(target)
	defer symb.Close()

	frames, err := symb.Symbolize(vmlinux, targetUnit.PCs...)
	if err != nil {
		return 0, fmt.Errorf("failed to symbolize KCOV PCs for %s: %w", filePath, err)
	}

	var (
		bestPC   uint64
		bestLine int
	)

	for _, frame := range frames {
		if frame.Line == line {
			return frame.PC, nil
		}
		if frame.Line <= line && frame.Line > bestLine {
			bestLine = frame.Line
			bestPC = frame.PC
		}
	}

	if bestPC != 0 {
		return bestPC, nil
	}
	return 0, fmt.Errorf("no KCOV coverage PC found for %s:%d", filePath, line)
}

func matchDwarfFile(fileName, cleanTargetFile string, kernelDirs *mgrconfig.KernelDirs) bool {
	cleanFile, _ := backend.CleanPath(fileName, kernelDirs, nil)
	if cleanFile == "" {
		cleanFile = filepath.Clean(fileName)
	}
	return cleanFile == cleanTargetFile ||
		strings.HasSuffix(cleanFile, "/"+cleanTargetFile) ||
		strings.HasSuffix(cleanTargetFile, "/"+cleanFile)
}
