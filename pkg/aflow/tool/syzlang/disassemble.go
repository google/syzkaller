// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package syzlang

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/google/syzkaller/pkg/aflow"
)

const (
	disassembleAddressRadius = 0x200
	disassembleContextLines  = 50
)

var DisassembleContext = aflow.NewFuncTool("disassemble-context", disassembleContext, `
Tool returns the source-interleaved disassembly around candidate target PC addresses.
Use this to understand compiler-injected instrumentation (e.g., KCOV, ASAN)
and low-level execution context of target code points.
Returns +/- 50 lines of objdump output centered around the first target PC, with candidate target PCs marked.
If you need to scroll, call the tool again with the first or last PC visible in the snippet in the PCs list.
`)

type DisassembleContextArgs struct {
	PCs []string `jsonschema:"List of candidate target raw un-relocated PC addresses (hex format)."`
}

type DisassembleContextResult struct {
	Output string `jsonschema:"The source-interleaved disassembly snippet."`
}

func disassembleContext(
	ctx *aflow.Context, state reproduceState, args DisassembleContextArgs,
) (DisassembleContextResult, error) {
	var rawPCs []string
	for _, p := range args.PCs {
		p = strings.TrimSpace(p)
		if p != "" && !slices.Contains(rawPCs, p) {
			rawPCs = append(rawPCs, p)
		}
	}
	if len(rawPCs) == 0 {
		return DisassembleContextResult{}, aflow.BadCallError("no PC provided")
	}

	var pcs []uint64
	for _, raw := range rawPCs {
		raw = strings.TrimSpace(raw)
		raw = strings.TrimPrefix(raw, "0x")
		pc, err := strconv.ParseUint(raw, 16, 64)
		if err != nil {
			return DisassembleContextResult{}, aflow.BadCallError("invalid pc format: %v", err)
		}
		pcs = append(pcs, pc)
	}

	snippet, err := doDisassembleContext(pcs, state.KernelObj, state.KernelSrc)
	if err != nil {
		return DisassembleContextResult{}, aflow.BadCallError("%v", err)
	}

	return DisassembleContextResult{Output: snippet}, nil
}

func doDisassembleContext(pcs []uint64, kernelObj, kernelSrc string) (string, error) {
	if len(pcs) == 0 {
		return "", fmt.Errorf("no target PC provided")
	}
	pc := pcs[0]
	vmlinux := filepath.Join(kernelObj, "vmlinux")
	startAddr, stopAddr := computeAddressBounds(pc)

	cmd := exec.Command("llvm-objdump", "-d", "-S",
		fmt.Sprintf("--start-address=0x%x", startAddr),
		fmt.Sprintf("--stop-address=0x%x", stopAddr),
		vmlinux)
	cmd.Dir = kernelSrc
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("llvm-objdump failed: %w\nOutput: %s", err, string(out))
	}

	return formatDisassemblySnippet(string(out), pcs), nil
}

func computeAddressBounds(pc uint64) (uint64, uint64) {
	startAddr := uint64(0)
	if pc > disassembleAddressRadius {
		startAddr = pc - disassembleAddressRadius
	}
	stopAddr := pc + disassembleAddressRadius
	if stopAddr < pc {
		stopAddr = ^uint64(0)
	}
	return startAddr, stopAddr
}

// formatDisassemblySnippet processes the raw objdump output to annotate target
// and candidate PCs, centers the output around the target PC (or the closest
// preceding instruction if the PC does not land on an exact instruction
// boundary), and slices a +/-disassembleContextLines context window.
func formatDisassemblySnippet(out string, pcs []uint64) string {
	if len(pcs) == 0 {
		return out
	}
	pc := pcs[0]
	lines := strings.Split(out, "\n")

	targetIdx := -1
	closestDist := uint64(0xffffffffffffffff)
	exactMatch := false

	for i, line := range lines {
		addrStr, _, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}

		addrStr = strings.TrimSpace(addrStr)
		addr, err := strconv.ParseUint(addrStr, 16, 64)
		if err == nil {
			if addr == pc {
				lines[i] = lines[i] + "  <-- TARGET PC"
				targetIdx = i
				exactMatch = true
			} else if slices.Contains(pcs, addr) {
				lines[i] = lines[i] + "  <-- CANDIDATE TARGET PC"
			}
			// If no exact instruction boundary matched the target PC yet, track the closest
			// instruction preceding pc so the context window remains centered near the target site.
			if !exactMatch && addr < pc {
				dist := pc - addr
				if dist < closestDist {
					closestDist = dist
					targetIdx = i
				}
			}
		}
	}

	// Default to centering in the middle of output if no address could be parsed.
	if targetIdx == -1 {
		targetIdx = len(lines) / 2
	}

	// Slice a +/-disassembleContextLines window around targetIdx.
	startIdx := max(0, targetIdx-disassembleContextLines)
	endIdx := min(len(lines), targetIdx+disassembleContextLines)

	snippetLines := lines[startIdx:endIdx]
	snippet := strings.Join(snippetLines, "\n")

	hasSource := false
	for _, l := range lines {
		if strings.HasPrefix(strings.TrimSpace(l), ";") {
			hasSource = true
			break
		}
	}

	if !hasSource {
		warn := "WARNING: Missing debug symbols or source code not found. " +
			"Returning raw assembly without interleaved C source lines.\n\n"
		snippet = warn + snippet
	}

	if len(pcs) > 1 {
		var candidateStrs []string
		for _, p := range pcs {
			candidateStrs = append(candidateStrs, fmt.Sprintf("0x%x", p))
		}
		header := fmt.Sprintf("Candidate Target PCs: %s\n\n", strings.Join(candidateStrs, ", "))
		snippet = header + snippet
	}

	return snippet
}
