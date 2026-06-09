// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package syzlang

import (
	"fmt"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/google/syzkaller/pkg/aflow"
)

var DisassembleContext = aflow.NewFuncTool("disassemble-context", disassembleContext, `
Tool returns the source-interleaved disassembly around a given PC.
Use this to understand the compiler-injected instrumentations (e.g. KCOV, ASAN)
and low-level execution context of a specific code point.
Returns +/- 50 lines of objdump output around the target PC.
If you need to scroll, call the tool again with the first or last PC visible in the snippet.
`)

type DisassembleContextArgs struct {
	PC string `jsonschema:"The raw un-relocated PC address (hex format, e.g., '0xffffffff817b73a0')."`
}

type DisassembleContextResult struct {
	Output string `jsonschema:"The source-interleaved disassembly snippet."`
}

func disassembleContext(
	ctx *aflow.Context, state reproduceState, args DisassembleContextArgs,
) (DisassembleContextResult, error) {
	raw := strings.TrimSpace(args.PC)
	raw = strings.TrimPrefix(raw, "0x")
	pc, err := strconv.ParseUint(raw, 16, 64)
	if err != nil {
		return DisassembleContextResult{}, aflow.BadCallError("invalid pc format: %v", err)
	}

	snippet, err := doDisassembleContext(pc, state.KernelObj, state.KernelSrc)
	if err != nil {
		return DisassembleContextResult{}, aflow.BadCallError("%v", err)
	}

	return DisassembleContextResult{Output: snippet}, nil
}

func doDisassembleContext(pc uint64, kernelObj, kernelSrc string) (string, error) {
	vmlinux := filepath.Join(kernelObj, "vmlinux")
	startAddr := pc - 0x200
	stopAddr := pc + 0x200

	cmd := exec.Command("llvm-objdump", "-d", "-S",
		fmt.Sprintf("--start-address=0x%x", startAddr),
		fmt.Sprintf("--stop-address=0x%x", stopAddr),
		vmlinux)
	cmd.Dir = kernelSrc
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("llvm-objdump failed: %w\nOutput: %s", err, string(out))
	}

	lines := strings.Split(string(out), "\n")

	targetIdx := -1
	closestDist := uint64(0xffffffffffffffff)

	for i, line := range lines {
		addrStr, _, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}

		addrStr = strings.TrimSpace(addrStr)
		addr, err := strconv.ParseUint(addrStr, 16, 64)
		if err == nil {
			if addr == pc {
				targetIdx = i
				break
			} else if addr < pc {
				dist := pc - addr
				if dist < closestDist {
					closestDist = dist
					targetIdx = i
				}
			}
		}
	}

	if targetIdx == -1 {
		targetIdx = len(lines) / 2
	}

	startIdx := max(0, targetIdx-20)
	endIdx := min(len(lines), targetIdx+20)

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

	return snippet, nil
}
