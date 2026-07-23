// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package seedgen

import (
	"debug/dwarf"
	"debug/elf"
	"encoding/json"
	"fmt"
	"io"
	"path/filepath"
	"slices"
	"strings"

	"github.com/google/syzkaller/docs"
	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/action/crash"
	"github.com/google/syzkaller/pkg/aflow/action/kernel"
	"github.com/google/syzkaller/pkg/aflow/ai"
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
	PC  string   `jsonschema:"Primary target PC (hex format)."`
	PCs []string `jsonschema:"All candidate KCOV PCs corresponding to this file and line (hex format)."`
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

	primaryPC := ""
	if len(hexPCs) > 0 {
		primaryPC = hexPCs[0]
	}

	return ResolveLineToPCResult{
		PC:  primaryPC,
		PCs: hexPCs,
	}, nil
}

func resolveLineToPCs(kernelSrc, kernelObj, filePath string, line int) ([]uint64, error) {
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
		return nil, fmt.Errorf("failed to build coverage backend: %w", err)
	}

	cleanTargetFile, _ := backend.CleanPath(filePath, kernelDirs, nil)
	if cleanTargetFile == "" {
		cleanTargetFile = filepath.Clean(filePath)
	}

	// Step 1: Collect KCOV PCs across ALL matching compile units (supports .h header files)
	var candidateKcovPCs []uint64
	for _, unit := range impl.Units {
		if matchDwarfFile(unit.Path, cleanTargetFile, kernelDirs) {
			candidateKcovPCs = append(candidateKcovPCs, unit.PCs...)
		}
	}

	if len(candidateKcovPCs) == 0 {
		return nil, fmt.Errorf("file %q not found or has no KCOV coverage points", filePath)
	}

	lineTable, err := loadLineTable(vmlinux, cleanTargetFile, kernelDirs)
	if err != nil {
		return nil, err
	}

	// Step 2: Symbolize all collected candidate PCs.
	symb := symbolizer.Make(target)
	defer symb.Close()

	frames, err := symb.Symbolize(vmlinux, candidateKcovPCs...)
	if err != nil {
		return nil, fmt.Errorf("failed to symbolize KCOV PCs for %s: %w", filePath, err)
	}

	pcToFrames := make(map[uint64][]symbolizer.Frame)
	for _, frame := range frames {
		pcToFrames[frame.PC] = append(pcToFrames[frame.PC], frame)
	}

	pcs, err := matchCandidatePCs(pcToFrames, lineTable, cleanTargetFile, kernelDirs, line)
	if err != nil {
		return nil, fmt.Errorf("no KCOV coverage PC found for %s:%d", filePath, line)
	}
	return pcs, nil
}

type lineEntry struct {
	addr uint64
	line int
}

func loadLineTable(vmlinux, cleanTargetFile string, kernelDirs *mgrconfig.KernelDirs) ([]lineEntry, error) {
	f, err := elf.Open(vmlinux)
	if err != nil {
		return nil, fmt.Errorf("failed to open vmlinux: %w", err)
	}
	defer f.Close()

	d, err := f.DWARF()
	if err != nil {
		return nil, fmt.Errorf("failed to read DWARF info: %w", err)
	}

	var lineTable []lineEntry
	r := d.Reader()
	for {
		entry, err := r.Next()
		if err != nil || entry == nil {
			break
		}

		if entry.Tag != dwarf.TagCompileUnit {
			continue
		}

		if entry.Children {
			r.SkipChildren()
		}

		entries, err := processCompileUnit(d, entry, cleanTargetFile, kernelDirs)
		if err != nil {
			return nil, err
		}
		lineTable = append(lineTable, entries...)
	}

	// Sort lineTable by address.
	slices.SortFunc(lineTable, func(a, b lineEntry) int {
		if a.addr < b.addr {
			return -1
		}
		if a.addr > b.addr {
			return 1
		}
		return 0
	})

	return lineTable, nil
}

func processCompileUnit(d *dwarf.Data, entry *dwarf.Entry,
	cleanTargetFile string, kernelDirs *mgrconfig.KernelDirs) ([]lineEntry, error) {
	isHeader := strings.HasSuffix(cleanTargetFile, ".h")
	if !isHeader {
		if nameAttr, ok := entry.Val(dwarf.AttrName).(string); ok {
			if !matchDwarfFile(nameAttr, cleanTargetFile, kernelDirs) {
				return nil, nil
			}
		}
	}

	lr, err := d.LineReader(entry)
	if err != nil {
		return nil, fmt.Errorf("failed to get LineReader: %w", err)
	}
	if lr == nil {
		return nil, nil
	}

	// Verify this Compile Unit contains the target file.
	hasTargetFile := false
	for _, file := range lr.Files() {
		if file != nil && matchDwarfFile(file.Name, cleanTargetFile, kernelDirs) {
			hasTargetFile = true
			break
		}
	}
	if !hasTargetFile {
		return nil, nil
	}

	var lineTable []lineEntry
	var le dwarf.LineEntry
	for {
		err := lr.Next(&le)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to read line table entry: %w", err)
		}
		if le.File != nil && matchDwarfFile(le.File.Name, cleanTargetFile, kernelDirs) {
			lineTable = append(lineTable, lineEntry{addr: le.Address, line: le.Line})
		}
	}
	return lineTable, nil
}

func matchCandidatePCs(pcToFrames map[uint64][]symbolizer.Frame,
	lineTable []lineEntry, cleanTargetFile string,
	kernelDirs *mgrconfig.KernelDirs, targetLine int) ([]uint64, error) {
	infos := collectPCInfos(pcToFrames, lineTable, cleanTargetFile, kernelDirs)

	// 1. Group by function, and find the closest preceding function start line.
	bestDist := -1
	var bestFuncs []string

	for _, info := range infos {
		if targetLine >= info.lStart {
			dist := targetLine - info.lStart
			if bestDist == -1 || dist < bestDist {
				bestDist = dist
				bestFuncs = []string{info.fun}
			} else if dist == bestDist {
				bestFuncs = append(bestFuncs, info.fun)
			}
		}
	}

	if len(bestFuncs) == 0 {
		return nil, fmt.Errorf("no KCOV coverage PC found")
	}

	// 2. Filter infos to only include the best functions, and apply interval check.
	type matchedPC struct {
		pc     uint64
		lStart int
	}
	var (
		matched     []matchedPC
		fallbackPCs []uint64
		bestLine    int
	)

	for _, info := range infos {
		if !slices.Contains(bestFuncs, info.fun) {
			continue
		}

		// Check if targetLine falls inside [lStart, lNext)
		if info.lNext > info.lStart && targetLine >= info.lStart && targetLine < info.lNext {
			matched = append(matched, matchedPC{pc: info.pc, lStart: info.lStart})
		}

		// Keep track of fallback PCs with the closest preceding line within the function.
		if targetLine >= info.lStart {
			if info.lStart > bestLine {
				bestLine = info.lStart
				fallbackPCs = []uint64{info.pc}
			} else if info.lStart == bestLine {
				fallbackPCs = append(fallbackPCs, info.pc)
			}
		}
	}

	// Return matched PCs filtered by maximum lStart (closest match).
	if len(matched) > 0 {
		maxLStart := 0
		for _, m := range matched {
			maxLStart = max(maxLStart, m.lStart)
		}
		var result []uint64
		for _, m := range matched {
			if m.lStart == maxLStart {
				result = append(result, m.pc)
			}
		}
		return slices.Compact(result), nil
	}

	if len(fallbackPCs) > 0 {
		return slices.Compact(fallbackPCs), nil
	}

	return nil, fmt.Errorf("no KCOV coverage PC found")
}

type pcInfo struct {
	pc     uint64
	lStart int
	lNext  int
	fun    string
}

func collectPCInfos(pcToFrames map[uint64][]symbolizer.Frame, lineTable []lineEntry,
	cleanTargetFile string, kernelDirs *mgrconfig.KernelDirs) []pcInfo {
	// Helper to find the next line table entry's line number in the target file.
	getNextLine := func(pc uint64) int {
		idx, found := slices.BinarySearchFunc(lineTable, lineEntry{addr: pc}, func(a, b lineEntry) int {
			if a.addr < b.addr {
				return -1
			}
			if a.addr > b.addr {
				return 1
			}
			return 0
		})
		if !found {
			if idx >= len(lineTable) {
				return 0 // No next line.
			}
		} else {
			idx++
		}

		currentLine := lineTable[idx-1].line
		for idx < len(lineTable) {
			if lineTable[idx].line != currentLine && lineTable[idx].line != 0 {
				return lineTable[idx].line
			}
			idx++
		}
		return 0
	}

	var infos []pcInfo
	for pc, pcFrames := range pcToFrames {
		// Find the innermost matching frame for the target file.
		var targetFrame *symbolizer.Frame
		for i := range pcFrames {
			if matchDwarfFile(pcFrames[i].File, cleanTargetFile, kernelDirs) {
				targetFrame = &pcFrames[i]
				break
			}
		}

		if targetFrame == nil {
			continue
		}

		infos = append(infos, pcInfo{
			pc:     pc,
			lStart: targetFrame.Line,
			lNext:  getNextLine(pc),
			fun:    targetFrame.Func,
		})
	}
	return infos
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
