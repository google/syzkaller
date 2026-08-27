// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package actionsyzlang

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"sync"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/action/crash"
	"github.com/google/syzkaller/pkg/aflow/syzspec"
	"github.com/google/syzkaller/pkg/cover/backend"
	"github.com/google/syzkaller/pkg/db"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/log"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/symbolizer"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
	"golang.org/x/sync/errgroup"
)

type ExecuteCorpusArgs struct {
	CorpusPath    string `json:",omitempty"`
	TargetOS      string
	TargetArch    string
	Syzkaller     string
	Image         string
	Type          string
	VM            json.RawMessage
	CorpusVMCount int `json:",omitempty"`
	KernelSrc     string
	KernelObj     string
	KernelCommit  string
}

type ExecuteCorpusResult struct {
	CorpusDir string
}

const (
	maxInflightPrograms         = 1000
	targetBucketSizeBytes       = 50 * 1024 * 1024
	maxIndexedProgramsPerTarget = 50
)

var ActionExecuteCorpus = aflow.NewFuncAction("execute-corpus", executeCorpusAction)

func executeCorpusAction(ctx *aflow.Context, args ExecuteCorpusArgs) (ExecuteCorpusResult, error) {
	if args.CorpusPath == "" {
		return ExecuteCorpusResult{}, nil
	}
	if args.CorpusVMCount <= 0 {
		return ExecuteCorpusResult{}, fmt.Errorf("corpusVMCount is not provided but is required for ActionExecuteCorpus")
	}

	corpusBytes, err := os.ReadFile(args.CorpusPath)
	if err != nil {
		return ExecuteCorpusResult{}, fmt.Errorf("failed to read corpus file: %w", err)
	}
	corpusSig := hash.String(corpusBytes)

	target, err := prog.GetTarget(args.TargetOS, args.TargetArch)
	if err != nil {
		return ExecuteCorpusResult{}, fmt.Errorf("unknown target: %s/%s", args.TargetOS, args.TargetArch)
	}
	sysTarget := targets.Get(args.TargetOS, args.TargetArch)
	if sysTarget == nil {
		return ExecuteCorpusResult{}, fmt.Errorf("unknown sys target: %s/%s", args.TargetOS, args.TargetArch)
	}

	corpusDB, err := db.Open(args.CorpusPath, false)
	if err != nil {
		return ExecuteCorpusResult{}, fmt.Errorf("failed to open corpus db: %w", err)
	}
	sortedKeys := slices.Sorted(maps.Keys(corpusDB.Records))
	if len(sortedKeys) == 0 {
		return ExecuteCorpusResult{}, nil
	}

	desc := fmt.Sprintf("corpus-execution-v1-%v-%v", args.KernelCommit, corpusSig)
	dir, err := ctx.Cache("corpus-execution", desc, func(dir string) error {
		log.Logf(1, "aflow: executing corpus from %q (%d programs)", args.CorpusPath, len(sortedKeys))
		// Preserve custom VM settings (memory, QEMU flags, disk images) while setting instance count.
		var vmConfig map[string]any
		if len(args.VM) > 0 {
			if err := json.Unmarshal(args.VM, &vmConfig); err != nil {
				return fmt.Errorf("failed to parse VM config: %w", err)
			}
		}
		if vmConfig == nil {
			vmConfig = make(map[string]any)
		}
		vmConfig["count"] = args.CorpusVMCount
		if b, err := json.Marshal(vmConfig); err != nil {
			return fmt.Errorf("failed to serialize VM config: %w", err)
		} else {
			args.VM = b
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
			Sandbox:      "none",
		}

		workdir, err := ctx.TempDir()
		if err != nil {
			return fmt.Errorf("failed to create workdir: %w", err)
		}
		defer os.RemoveAll(workdir)

		cfg, err := crash.BuildConfig(targetConfig, workdir)
		if err != nil {
			return fmt.Errorf("failed to build config: %w", err)
		}

		err = aflow.RunIsolatedManager(ctx.Context, cfg, false, func(mgrCtx context.Context, rm *aflow.RunnerManager) error {
			return streamExecuteCorpus(mgrCtx, rm, streamCorpusParams{
				dir:        dir,
				records:    corpusDB.Records,
				sortedKeys: sortedKeys,
				target:     target,
				sysTarget:  sysTarget,
				vmType:     args.Type,
				kernelObj:  args.KernelObj,
			})
		})
		if err != nil {
			return fmt.Errorf("failed to execute corpus: %w", err)
		}
		return nil
	})
	if err != nil {
		return ExecuteCorpusResult{}, fmt.Errorf("failed to cache corpus execution: %w", err)
	}

	return ExecuteCorpusResult{CorpusDir: dir}, nil
}

// rollingBucketWriter buffers serialized programs in memory and flushes them
// to bucket files once the buffer reaches targetSizeBytes.
type rollingBucketWriter struct {
	dir               string
	targetSizeBytes   int
	currentBucket     map[string]string
	currentBucketSize int
	currentBucketIdx  int
}

func newRollingBucketWriter(dir string, targetSizeBytes int) *rollingBucketWriter {
	return &rollingBucketWriter{
		dir:             dir,
		targetSizeBytes: targetSizeBytes,
		currentBucket:   make(map[string]string),
	}
}

// addProgram adds a serialized program to the current bucket, flushing to disk if full.
// Returns the bucket file name where the program was stored.
func (w *rollingBucketWriter) addProgram(pHash, pData string) (string, error) {
	pSize := len(pHash) + len(pData)
	if w.currentBucketSize > 0 && w.currentBucketSize+pSize > w.targetSizeBytes {
		if err := w.finishCurrent(); err != nil {
			return "", err
		}
	}
	w.currentBucket[pHash] = pData
	w.currentBucketSize += pSize
	return syzspec.CorpusBucketFileName(w.currentBucketIdx), nil
}

func (w *rollingBucketWriter) finishCurrent() error {
	if len(w.currentBucket) == 0 {
		return nil
	}
	if _, err := syzspec.SaveCorpusBucket(w.dir, w.currentBucketIdx, w.currentBucket); err != nil {
		return err
	}
	w.currentBucket = make(map[string]string)
	w.currentBucketSize = 0
	w.currentBucketIdx++
	return nil
}

func (w *rollingBucketWriter) finalize() error {
	return w.finishCurrent()
}

// incrementalIndexBuilder builds reachability mappings from functions and syscalls
// to program hashes while enforcing a per-target program cap.
type incrementalIndexBuilder struct {
	functionMap    map[string][]string
	syscallMap     map[string][]string
	progToBucket   map[string]string
	functionHashes map[string]map[string]bool
	syscallHashes  map[string]map[string]bool
}

func newIncrementalIndexBuilder() *incrementalIndexBuilder {
	return &incrementalIndexBuilder{
		functionMap:    make(map[string][]string),
		syscallMap:     make(map[string][]string),
		progToBucket:   make(map[string]string),
		functionHashes: make(map[string]map[string]bool),
		syscallHashes:  make(map[string]map[string]bool),
	}
}

func (b *incrementalIndexBuilder) isSaturated(name string) bool {
	return len(b.functionMap[name]) >= maxIndexedProgramsPerTarget
}

func (b *incrementalIndexBuilder) recordProgBucket(pHash, bucketFile string) {
	b.progToBucket[pHash] = bucketFile
}

func (b *incrementalIndexBuilder) addFunctionProgram(funcName, pHash string) {
	b.addProgram(b.functionMap, b.functionHashes, funcName, pHash)
}

func (b *incrementalIndexBuilder) addSyscallProgram(syscallName, pHash string) {
	b.addProgram(b.syscallMap, b.syscallHashes, syscallName, pHash)
}

func (b *incrementalIndexBuilder) addProgram(targetMap map[string][]string,
	hashesMap map[string]map[string]bool, name, pHash string) {
	if len(targetMap[name]) >= maxIndexedProgramsPerTarget {
		return
	}
	if hashesMap[name] == nil {
		hashesMap[name] = make(map[string]bool)
	}
	if hashesMap[name][pHash] {
		return
	}
	hashesMap[name][pHash] = true
	targetMap[name] = append(targetMap[name], pHash)
}

type streamCorpusParams struct {
	dir        string
	records    map[string]db.Record
	sortedKeys []string
	target     *prog.Target
	sysTarget  *targets.Target
	vmType     string
	kernelObj  string
}

type completedProg struct {
	pHash string
	res   *queue.Result
}

// streamExecuteCorpus streams programs continuously across the VM pool via a sliding window,
// writes bucket files, and builds the search index.
func streamExecuteCorpus(ctx context.Context, rm *aflow.RunnerManager, params streamCorpusParams) error {
	symb := symbolizer.Make(params.sysTarget)
	defer symb.Close()

	streamer := newCorpusStreamer(rm, params, symb)
	return streamer.run(ctx)
}

type corpusStreamer struct {
	rm           *aflow.RunnerManager
	params       streamCorpusParams
	vmlinux      string
	symb         symbolizer.Symbolizer
	bucketWriter *rollingBucketWriter
	indexBuilder *incrementalIndexBuilder
	pcCache      map[uint64][]string
	resultsChan  chan completedProg
}

func newCorpusStreamer(rm *aflow.RunnerManager, params streamCorpusParams, symb symbolizer.Symbolizer) *corpusStreamer {
	return &corpusStreamer{
		rm:           rm,
		params:       params,
		vmlinux:      filepath.Join(params.kernelObj, params.sysTarget.KernelObject),
		symb:         symb,
		bucketWriter: newRollingBucketWriter(params.dir, targetBucketSizeBytes),
		indexBuilder: newIncrementalIndexBuilder(),
		pcCache:      make(map[uint64][]string),
		resultsChan:  make(chan completedProg, maxInflightPrograms),
	}
}

func (s *corpusStreamer) run(ctx context.Context) error {
	eg, egCtx := errgroup.WithContext(ctx)

	eg.Go(func() error {
		return s.feedPrograms(egCtx)
	})

	eg.Go(func() error {
		return s.consumeResults(egCtx)
	})

	if err := eg.Wait(); err != nil {
		return fmt.Errorf("failed to stream corpus execution: %w", err)
	}

	if err := s.bucketWriter.finalize(); err != nil {
		return err
	}

	indexData := syzspec.CorpusData{
		FunctionMap:  s.indexBuilder.functionMap,
		SyscallMap:   s.indexBuilder.syscallMap,
		ProgToBucket: s.indexBuilder.progToBucket,
	}

	if err := osutil.WriteJSON(filepath.Join(s.params.dir, "index.json"), indexData); err != nil {
		return fmt.Errorf("failed to write index.json: %w", err)
	}

	return nil
}

// feedPrograms feeds programs into RunnerManager using a sliding-window semaphore.
func (s *corpusStreamer) feedPrograms(ctx context.Context) error {
	// inflightSem acts as a sliding-window semaphore that caps concurrently pending
	// VM executions at maxInflightPrograms (1000) to prevent unbounded memory growth.
	inflightSem := osutil.NewSemaphore(maxInflightPrograms)
	var inflightWg sync.WaitGroup
	// Wait for in-flight callbacks (or abort on context cancellation) before closing resultsChan
	// to prevent writing to a closed channel or deadlocking on premature manager shutdown.
	defer func() {
		done := make(chan struct{})
		go func() {
			inflightWg.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-ctx.Done():
		}
		close(s.resultsChan)
	}()

	// seenHashes deduplicates programs across corpus DB records so identical programs
	// are not redundantly executed or duplicated across bucket partitions.
	seenHashes := make(map[string]bool)
	for _, k := range s.params.sortedKeys {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		rec := s.params.records[k]
		p, err := s.params.target.Deserialize(rec.Val, prog.NonStrict)
		if err != nil {
			log.Logf(1, "aflow: failed to deserialize program %s: %v", k, err)
			continue
		}
		pData := p.Serialize()
		pHash := hash.String(pData)
		if seenHashes[pHash] {
			continue
		}
		seenHashes[pHash] = true

		bucketFile, err := s.bucketWriter.addProgram(pHash, string(pData))
		if err != nil {
			return err
		}
		s.indexBuilder.recordProgBucket(pHash, bucketFile)

		// Build mapping from syscall names to program references.
		for _, call := range p.Calls {
			s.indexBuilder.addSyscallProgram(call.Meta.Name, pHash)
		}

		// Acquire a concurrency token; blocks if maxInflightPrograms are currently
		// executing in VMs.
		select {
		case <-inflightSem.WaitC():
		case <-ctx.Done():
			return ctx.Err()
		}

		inflightWg.Add(1)
		pHashCopy := pHash
		s.rm.SubmitAsync(p, func(res *queue.Result) {
			defer func() {
				inflightSem.Signal()
				inflightWg.Done()
			}()
			select {
			case s.resultsChan <- completedProg{
				pHash: pHashCopy,
				res:   res,
			}:
			case <-ctx.Done():
			}
		})
	}
	return nil
}

// consumeResults batches completed results, symbolizes coverage, and updates the index.
func (s *corpusStreamer) consumeResults(ctx context.Context) error {
	var batch []completedProg
	executedCount := 0

	for item := range s.resultsChan {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		batch = append(batch, item)
		executedCount++
		if len(batch) >= maxInflightPrograms {
			if err := s.processBatch(batch, executedCount); err != nil {
				return err
			}
			batch = nil
		}
	}

	return s.processBatch(batch, executedCount)
}

// processBatch extracts covered PCs from an accumulated batch, resolves symbol names via symbolizer,
// and updates function-to-program reachability mappings in the index builder.
func (s *corpusStreamer) processBatch(batch []completedProg, executedCount int) error {
	if len(batch) == 0 {
		return nil
	}
	pcToHashes := extractBatchCoverage(batch, s.params.sysTarget, s.params.vmType)
	if err := symbolizeBatchCoverage(s.symb, s.vmlinux, pcToHashes, s.pcCache, s.indexBuilder); err != nil {
		return err
	}
	log.Logf(2, "aflow: %d/%d executed", executedCount, len(s.params.sortedKeys))
	return nil
}

// extractBatchCoverage extracts covered instruction PCs from execution results across both
// syscall calls and asynchronous Extra coverage (interrupts, background workqueues),
// mapping each PC to a sorted slice of unique program hashes.
func extractBatchCoverage(batch []completedProg, sysTarget *targets.Target,
	vmType string) map[uint64][]string {
	pcToHashes := make(map[uint64]map[string]bool)
	addCover := func(pHash string, cover []uint64) {
		if len(cover) == 0 {
			return
		}
		// Convert KCOV return addresses back to call sites / instruction addresses.
		for _, pc := range backend.PreviousInstructionPCs(sysTarget, vmType, cover) {
			if pcToHashes[pc] == nil {
				pcToHashes[pc] = make(map[string]bool)
			}
			pcToHashes[pc][pHash] = true
		}
	}

	for _, item := range batch {
		if item.res == nil || item.res.Err != nil || item.res.Info == nil {
			continue
		}
		for _, call := range item.res.Info.Calls {
			addCover(item.pHash, call.Cover)
		}
		if item.res.Info.Extra != nil {
			addCover(item.pHash, item.res.Info.Extra.Cover)
		}
	}

	// Sort program hashes deterministically for reproducible index outputs.
	result := make(map[uint64][]string, len(pcToHashes))
	for pc, hashSet := range pcToHashes {
		hashes := slices.Collect(maps.Keys(hashSet))
		slices.Sort(hashes)
		result[pc] = hashes
	}
	return result
}

// symbolizeBatchCoverage resolves function names for covered PCs and registers them in indexBuilder.
func symbolizeBatchCoverage(symb symbolizer.Symbolizer, vmlinux string,
	pcToHashes, pcCache map[uint64][]string,
	indexBuilder *incrementalIndexBuilder) error {
	if len(pcToHashes) == 0 {
		return nil
	}

	// Phase 1: Batch-query symbolizer for uncached PCs (sorted for optimal addr2line binary search locality).
	var uncachedPCs []uint64
	for pc := range pcToHashes {
		if _, cached := pcCache[pc]; !cached {
			uncachedPCs = append(uncachedPCs, pc)
		}
	}

	if len(uncachedPCs) > 0 {
		slices.Sort(uncachedPCs)
		frames, err := symb.Symbolize(vmlinux, uncachedPCs...)
		if err != nil {
			return fmt.Errorf("failed to batch symbolize coverage: %w", err)
		}
		// Record negative cache hit (empty slice) so unresolved addresses are not queried again.
		for _, pc := range uncachedPCs {
			pcCache[pc] = nil
		}
		for _, frame := range frames {
			if frame.Func != "" && !slices.Contains(pcCache[frame.PC], frame.Func) {
				pcCache[frame.PC] = append(pcCache[frame.PC], frame.Func)
			}
		}
	}

	// Phase 2: Single unified mapping pass from resolved functions to program hashes.
	for pc, hashes := range pcToHashes {
		for _, funcName := range pcCache[pc] {
			if indexBuilder.isSaturated(funcName) {
				continue
			}
			for _, pHash := range hashes {
				indexBuilder.addFunctionProgram(funcName, pHash)
			}
		}
	}
	return nil
}
