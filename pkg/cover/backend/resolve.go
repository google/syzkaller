// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package backend

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"github.com/google/syzkaller/pkg/vminfo"
)

// ResolveLineToPCs resolves a source code location (filePath and line) to candidate
// KCOV coverage callback PCs (__sanitizer_cov_trace_pc).
func (impl *Impl) ResolveLineToPCs(filePath string, line int) ([]uint64, error) {
	if filePath == "" || line <= 0 {
		return nil, fmt.Errorf("both filePath and a positive line number must be provided")
	}

	frames := impl.findFramesForFile(filePath)
	if len(frames) == 0 {
		pcsByMod := impl.candidatePCs(filePath)
		if len(pcsByMod) == 0 {
			return nil, fmt.Errorf("no KCOV coverage points found for file %q", filePath)
		}
		newFrames, err := impl.Symbolize(pcsByMod)
		if err != nil {
			return nil, fmt.Errorf("failed to symbolize candidate PCs for %s: %w", filePath, err)
		}
		impl.Frames = append(impl.Frames, newFrames...)
		frames = impl.findFramesForFile(filePath)
	}

	if len(frames) == 0 {
		return nil, fmt.Errorf("no KCOV coverage points found for file %q", filePath)
	}

	return matchFrames(frames, line)
}

func (impl *Impl) findFramesForFile(filePath string) []*Frame {
	var res []*Frame
	for _, f := range impl.Frames {
		if matchPath(f.Name, filePath) || matchPath(f.Path, filePath) {
			res = append(res, f)
		}
	}
	return res
}

func (impl *Impl) candidatePCs(filePath string) map[*vminfo.KernelModule][]uint64 {
	pcsByMod := make(map[*vminfo.KernelModule][]uint64)
	for _, unit := range impl.Units {
		if matchPath(unit.Name, filePath) || matchPath(unit.Path, filePath) {
			pcsByMod[unit.Module] = append(pcsByMod[unit.Module], unit.PCs...)
		}
	}
	if len(pcsByMod) == 0 && isHeaderFile(filePath) {
		// If no compile unit matches directly, filePath may be a header file (.h)
		// included across compile units. Fall back to all compile units.
		for _, unit := range impl.Units {
			pcsByMod[unit.Module] = append(pcsByMod[unit.Module], unit.PCs...)
		}
	}
	for mod, pcs := range pcsByMod {
		slices.Sort(pcs)
		pcsByMod[mod] = slices.Compact(pcs)
	}
	return pcsByMod
}

func isHeaderFile(filePath string) bool {
	return filepath.Ext(filePath) == ".h"
}

func matchPath(path1, path2 string) bool {
	p1 := filepath.ToSlash(filepath.Clean(path1))
	p2 := filepath.ToSlash(filepath.Clean(path2))
	return p1 == p2 || strings.HasSuffix(p1, "/"+p2) || strings.HasSuffix(p2, "/"+p1)
}

func matchFrames(frames []*Frame, targetLine int) ([]uint64, error) {
	funcs := make(map[string][]*Frame)
	for _, f := range frames {
		funcs[f.FuncName] = append(funcs[f.FuncName], f)
	}

	bestDist := -1
	var bestFuncs []string

	for fnName, fFrames := range funcs {
		for _, f := range fFrames {
			if targetLine >= f.Range.StartLine {
				dist := targetLine - f.Range.StartLine
				if bestDist == -1 || dist < bestDist {
					bestDist = dist
					bestFuncs = []string{fnName}
				} else if dist == bestDist && !slices.Contains(bestFuncs, fnName) {
					bestFuncs = append(bestFuncs, fnName)
				}
			}
		}
	}

	if bestDist == -1 {
		return nil, fmt.Errorf("no KCOV coverage PC found for line %d", targetLine)
	}

	bestLine := targetLine - bestDist
	var result []uint64
	for _, fnName := range bestFuncs {
		for _, f := range funcs[fnName] {
			if f.Range.StartLine == bestLine {
				result = append(result, f.PC)
			}
		}
	}

	slices.Sort(result)
	return slices.Compact(result), nil
}
