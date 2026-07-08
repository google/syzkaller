// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package seedgen

import (
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"runtime"
	"slices"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/action/crash"
	"github.com/google/syzkaller/pkg/cover/backend"
	"github.com/google/syzkaller/pkg/db"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/symbolizer"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

type ExecuteCorpusArgs struct {
	CorpusPath   string
	TargetOS     string
	TargetArch   string
	Syzkaller    string
	Image        string
	Type         string
	VM           json.RawMessage
	KernelSrc    string
	KernelObj    string
	KernelCommit string
}

type ExecuteCorpusResult struct {
	CorpusExecutionCachedID string
}

type corpusData struct {
	Programs    map[string]string   `json:"Programs"`
	FunctionMap map[string][]string `json:"FunctionMap"`
}

var ActionExecuteCorpus = aflow.NewFuncAction("execute-corpus", executeCorpusAction)

func executeCorpusAction(ctx *aflow.Context, args ExecuteCorpusArgs) (ExecuteCorpusResult, error) {
	if args.CorpusPath == "" {
		return ExecuteCorpusResult{}, fmt.Errorf("CorpusPath is not provided but is required for ActionExecuteCorpus")
	}

	corpusBytes, err := os.ReadFile(args.CorpusPath)
	if err != nil {
		return ExecuteCorpusResult{}, fmt.Errorf("failed to read corpus file: %w", err)
	}
	corpusSig := hash.String(corpusBytes)

	desc := fmt.Sprintf("corpus-execution-%v-%v", args.KernelCommit, corpusSig)
	_, cachedID, err := aflow.CacheObject(ctx, "corpus-execution", desc, func() (corpusData, error) {
		target, err := prog.GetTarget(args.TargetOS, args.TargetArch)
		if err != nil {
			return corpusData{}, fmt.Errorf("unknown target: %s/%s", args.TargetOS, args.TargetArch)
		}
		sysTarget := targets.Get(args.TargetOS, args.TargetArch)
		if sysTarget == nil {
			return corpusData{}, fmt.Errorf("unknown sys target: %s/%s", args.TargetOS, args.TargetArch)
		}

		log.Logf(0, "aflow: executing corpus from %q", args.CorpusPath)
		progs, err := db.ReadCorpus(args.CorpusPath, target)
		if err != nil {
			return corpusData{}, fmt.Errorf("failed to read corpus: %w", err)
		}
		if len(progs) == 0 {
			return corpusData{}, fmt.Errorf("corpus is empty")
		}

		corpusVMCount := max(1, int(float64(runtime.NumCPU())/2.5))

		var vmConfig map[string]any
		if err := json.Unmarshal(args.VM, &vmConfig); err == nil {
			vmConfig["count"] = corpusVMCount
			if b, err := json.Marshal(vmConfig); err == nil {
				args.VM = b
			}
		}

		targetConfig := crash.TargetConfig{
			AgentName:    "corpus-executor",
			TargetArch:   args.TargetArch,
			Syzkaller:    args.Syzkaller,
			Image:        args.Image,
			Type:         args.Type,
			VM:           args.VM,
			KernelSrc:    args.KernelSrc,
			KernelObj:    args.KernelObj,
			KernelCommit: args.KernelCommit,
			Snapshot:     false,
			Sandbox:      "namespace",
		}

		workdir, err := ctx.TempDir()
		if err != nil {
			return corpusData{}, fmt.Errorf("failed to create workdir: %w", err)
		}

		cfg, err := crash.BuildConfig(targetConfig, workdir)
		if err != nil {
			return corpusData{}, fmt.Errorf("failed to build config: %w", err)
		}

		var results []*queue.Result
		err = aflow.RunIsolatedManager(ctx.Context, cfg, false, func(rm *aflow.RunnerManager) error {
			var err error
			results, err = rm.SubmitBatch(ctx.Context, progs)
			return err
		})
		if err != nil {
			return corpusData{}, fmt.Errorf("failed to submit corpus for execution: %w", err)
		}

		programsMap, pcToProgHashes := collectPCs(results, progs, sysTarget, args.Type)

		functionMap := make(map[string]map[string]bool)
		if len(pcToProgHashes) > 0 {
			// Extract all unique PCs.
			uniquePCs := slices.Collect(maps.Keys(pcToProgHashes))
			vmlinux := filepath.Join(args.KernelObj, sysTarget.KernelObject)

			// Initialize a single symbolizer session.
			symb := symbolizer.Make(sysTarget)
			defer symb.Close()

			frames, err := symb.Symbolize(vmlinux, uniquePCs...)
			if err != nil {
				return corpusData{}, fmt.Errorf("failed to batch symbolize coverage: %w", err)
			}

			// Map symbolized functions back to their triggering program hashes.
			for _, frame := range frames {
				funcName := frame.Func
				if funcName == "" {
					continue
				}
				if functionMap[funcName] == nil {
					functionMap[funcName] = make(map[string]bool)
				}
				for pHash := range pcToProgHashes[frame.PC] {
					functionMap[funcName][pHash] = true
				}
			}
		}

		finalFunctionMap := make(map[string][]string)
		for fn, hashesMap := range functionMap {
			var hashes []string
			for h := range hashesMap {
				hashes = append(hashes, h)
			}
			finalFunctionMap[fn] = hashes
		}

		return corpusData{
			Programs:    programsMap,
			FunctionMap: finalFunctionMap,
		}, nil
	})
	if err != nil {
		return ExecuteCorpusResult{}, fmt.Errorf("failed to cache corpus execution: %w", err)
	}

	return ExecuteCorpusResult{CorpusExecutionCachedID: cachedID}, nil
}

func collectPCs(results []*queue.Result, progs []*prog.Prog, sysTarget *targets.Target, vmType string) (
	map[string]string, map[uint64]map[string]bool,
) {
	programsMap := make(map[string]string)
	pcToProgHashes := make(map[uint64]map[string]bool)

	for i, res := range results {
		if res.Err != nil || res.Info == nil {
			continue
		}

		p := progs[i]
		pData := p.Serialize()
		pHash := hash.String(pData)
		programsMap[pHash] = string(pData)

		for _, call := range res.Info.Calls {
			if len(call.Cover) == 0 {
				continue
			}
			// Adjust PCs to point to the actual call/instruction rather than the instruction after it.
			adjustedPCs := backend.PreviousInstructionPCs(sysTarget, vmType, call.Cover)
			for _, pc := range adjustedPCs {
				if pcToProgHashes[pc] == nil {
					pcToProgHashes[pc] = make(map[string]bool)
				}
				pcToProgHashes[pc][pHash] = true
			}
		}
	}
	return programsMap, pcToProgHashes
}
