// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package actionsyzlang

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/syzkaller/pkg/aflow"
	"github.com/google/syzkaller/pkg/aflow/syzspec"
	"github.com/google/syzkaller/pkg/db"
	"github.com/google/syzkaller/pkg/flatrpc"
	"github.com/google/syzkaller/pkg/fuzzer/queue"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/symbolizer"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
	"github.com/stretchr/testify/require"
)

func setupDummySyzkaller(t *testing.T) string {
	dir := t.TempDir()
	binDir := filepath.Join(dir, "bin", "linux_amd64")
	require.NoError(t, os.MkdirAll(binDir, 0755))
	for _, file := range []string{"syz-execprog", "syz-executor"} {
		require.NoError(t, os.WriteFile(filepath.Join(binDir, file), []byte("dummy"), 0644))
	}
	return dir
}

func createTestCorpus(t *testing.T, targetOS, targetArch string, progStrs []string) (string, []*prog.Prog) {
	target, err := prog.GetTarget(targetOS, targetArch)
	require.NoError(t, err)

	corpusPath := filepath.Join(t.TempDir(), "test_corpus.db")
	dbFile, err := db.Open(corpusPath, false)
	require.NoError(t, err)

	var progs []*prog.Prog
	for i, s := range progStrs {
		p, err := target.Deserialize([]byte(s), prog.NonStrict)
		require.NoError(t, err)
		progs = append(progs, p)
		pData := p.Serialize()
		dbFile.Save(fmt.Sprintf("prog_%d", i), pData, uint64(i))
	}
	require.NoError(t, dbFile.Flush())
	return corpusPath, progs
}

func TestExecuteCorpusAction_EmptyCorpusPath(t *testing.T) {
	ctx := aflow.NewTestContext(t)
	res, err := executeCorpusAction(ctx, ExecuteCorpusArgs{})
	require.NoError(t, err)
	require.Empty(t, res.CorpusDir)
}

func TestExecuteCorpusAction_FileNotFound(t *testing.T) {
	ctx := aflow.NewTestContext(t)
	_, err := executeCorpusAction(ctx, ExecuteCorpusArgs{
		CorpusPath:    filepath.Join(t.TempDir(), "nonexistent.db"),
		CorpusVMCount: 1,
	})
	require.ErrorContains(t, err, "failed to read corpus file")
}

func TestExecuteCorpusAction_InvalidTarget(t *testing.T) {
	ctx := aflow.NewTestContext(t)
	dummyPath := filepath.Join(t.TempDir(), "dummy.db")
	require.NoError(t, os.WriteFile(dummyPath, []byte("valid-file-header"), 0644))

	res, err := executeCorpusAction(ctx, ExecuteCorpusArgs{
		CorpusPath:    dummyPath,
		TargetOS:      "nonexistent_os",
		TargetArch:    "nonexistent_arch",
		CorpusVMCount: 1,
	})
	require.Empty(t, res.CorpusDir)
	require.ErrorContains(t, err, "unknown target: nonexistent_os/nonexistent_arch")
}

func TestExecuteCorpusAction_CorruptedCorpus(t *testing.T) {
	ctx := aflow.NewTestContext(t)
	corpusPath := filepath.Join(t.TempDir(), "corrupt.db")
	require.NoError(t, os.WriteFile(corpusPath, []byte("corrupted non-db content"), 0600))

	_, err := executeCorpusAction(ctx, ExecuteCorpusArgs{
		CorpusPath:    corpusPath,
		TargetOS:      "linux",
		TargetArch:    "amd64",
		CorpusVMCount: 1,
	})
	require.ErrorContains(t, err, "failed to open corpus db")
}

func TestExecuteCorpusAction_EmptyCorpus(t *testing.T) {
	ctx := aflow.NewTestContext(t)
	corpusPath := filepath.Join(t.TempDir(), "empty.db")
	dbFile, err := db.Open(corpusPath, false)
	require.NoError(t, err)
	require.NoError(t, dbFile.Flush())

	res, err := executeCorpusAction(ctx, ExecuteCorpusArgs{
		CorpusPath:    corpusPath,
		TargetOS:      "linux",
		TargetArch:    "amd64",
		CorpusVMCount: 1,
	})
	require.NoError(t, err)
	require.Empty(t, res.CorpusDir)
}

func TestExecuteCorpusAction_BuildConfigError(t *testing.T) {
	ctx := aflow.NewTestContext(t)
	corpusPath, _ := createTestCorpus(t, "linux", "amd64", []string{
		"getpid()",
	})

	_, err := executeCorpusAction(ctx, ExecuteCorpusArgs{
		CorpusPath:    corpusPath,
		TargetOS:      "linux",
		TargetArch:    "amd64",
		Type:          "unsupported_vm_type",
		CorpusVMCount: 1,
	})
	require.ErrorContains(t, err, "failed to build config")
}

func TestExecuteCorpusAction_RunIsolatedManagerFailure(t *testing.T) {
	ctx := aflow.NewTestContext(t)
	corpusPath, _ := createTestCorpus(t, "linux", "amd64", []string{
		"getpid()",
	})

	image := filepath.Join(t.TempDir(), "image")
	require.NoError(t, os.WriteFile(image, nil, 0600))

	// Calling with dummy image/kernel causes RunIsolatedManager's VM creation to fail.
	_, err := executeCorpusAction(ctx, ExecuteCorpusArgs{
		CorpusPath:    corpusPath,
		TargetOS:      "linux",
		TargetArch:    "amd64",
		Syzkaller:     setupDummySyzkaller(t),
		Image:         image,
		KernelSrc:     t.TempDir(),
		Type:          "qemu",
		KernelObj:     t.TempDir(),
		CorpusVMCount: 1,
	})
	require.ErrorContains(t, err, "failed to execute corpus")
}

func TestExecuteCorpusAction_MissingVMCount(t *testing.T) {
	ctx := aflow.NewTestContext(t)
	_, err := executeCorpusAction(ctx, ExecuteCorpusArgs{
		CorpusPath: "some/path.db",
	})
	require.EqualError(t, err, "corpusVMCount is not provided but is required for ActionExecuteCorpus")
}

func TestExtractBatchCoverage(t *testing.T) {
	sysTarget := targets.Get("linux", "amd64")

	// 1. Results with nil entry, error entry, nil Info, empty Cover.
	batch := []completedProg{
		{pHash: "h1", res: nil},
		{pHash: "h2", res: &queue.Result{Err: errors.New("exec error")}},
		{pHash: "h3", res: &queue.Result{Info: nil}},
	}
	pcToHashes := extractBatchCoverage(batch, sysTarget, "qemu")
	require.Empty(t, pcToHashes)

	// 2. Result with valid Info, Calls, and Extra.
	batch = []completedProg{
		{
			pHash: "h1",
			res: &queue.Result{
				Info: &flatrpc.ProgInfo{
					Calls: []*flatrpc.CallInfo{
						{Cover: nil},
						{Cover: []uint64{0x1005}},
					},
					Extra: &flatrpc.CallInfo{
						Cover: []uint64{0x2005},
					},
				},
			},
		},
		{
			pHash: "h2",
			res: &queue.Result{
				Info: &flatrpc.ProgInfo{
					Calls: []*flatrpc.CallInfo{
						{Cover: []uint64{0x1005}},
					},
				},
			},
		},
	}
	pcToHashes = extractBatchCoverage(batch, sysTarget, "qemu")
	require.Contains(t, pcToHashes, uint64(0x1000))
	require.Contains(t, pcToHashes, uint64(0x2000))
	require.Equal(t, []string{"h1", "h2"}, pcToHashes[uint64(0x1000)])
	require.Equal(t, []string{"h1"}, pcToHashes[uint64(0x2000)])
}

func TestSymbolizeBatchCoverage_Empty(t *testing.T) {
	sysTarget := targets.Get("linux", "amd64")
	symb := symbolizer.Make(sysTarget)
	defer symb.Close()

	builder := newIncrementalIndexBuilder()
	pcCache := make(map[uint64][]string)
	err := symbolizeBatchCoverage(symb, filepath.Join(t.TempDir(), "vmlinux"), nil, pcCache, builder)
	require.NoError(t, err)
	require.Empty(t, builder.functionMap)
}

func TestSymbolizeBatchCoverage_CachedHits(t *testing.T) {
	sysTarget := targets.Get("linux", "amd64")
	symb := symbolizer.Make(sysTarget)
	defer symb.Close()

	builder := newIncrementalIndexBuilder()
	pcCache := map[uint64][]string{
		0x1000: {"cached_fn"},
	}
	pcToHashes := map[uint64][]string{
		0x1000: {"h1"},
	}
	// With 0x1000 cached, it shouldn't even call symbolizer on the nonexistent vmlinux path.
	err := symbolizeBatchCoverage(symb, filepath.Join(t.TempDir(), "nonexistent"),
		pcToHashes, pcCache, builder)
	require.NoError(t, err)
	require.Equal(t, []string{"h1"}, builder.functionMap["cached_fn"])
}

func TestSymbolizeBatchCoverage_SymbolizerError(t *testing.T) {
	sysTarget := targets.Get("linux", "amd64")
	symb := symbolizer.Make(sysTarget)
	defer symb.Close()

	builder := newIncrementalIndexBuilder()
	pcCache := make(map[uint64][]string)
	pcToHashes := map[uint64][]string{
		0x1000: {"h1"},
	}
	err := symbolizeBatchCoverage(symb, filepath.Join(t.TempDir(), "nonexistent"),
		pcToHashes, pcCache, builder)
	require.ErrorContains(t, err, "failed to batch symbolize coverage")
}

func TestRollingBucketWriter(t *testing.T) {
	dir := t.TempDir()
	// Target size of 30 bytes to trigger bucket splits.
	w := newRollingBucketWriter(dir, 30)

	// "h1" + "prog1" = 7 bytes
	f1, err := w.addProgram("h1", "prog1")
	require.NoError(t, err)
	require.Equal(t, "bucket_000.json", f1)

	// "h2" + "prog2" = 7 bytes (total 14)
	f2, err := w.addProgram("h2", "prog2")
	require.NoError(t, err)
	require.Equal(t, "bucket_000.json", f2)

	// "h3" + "large_prog_exceeding_bucket_limit" = 36 bytes (flushes bucket 0, starts bucket 1)
	f3, err := w.addProgram("h3", "large_prog_exceeding_bucket_limit")
	require.NoError(t, err)
	require.Equal(t, "bucket_001.json", f3)

	err = w.finalize()
	require.NoError(t, err)

	// Verify bucket 0 contents on disk.
	b0, err := osutil.ReadJSON[syzspec.CorpusProgramBucket](filepath.Join(dir, "bucket_000.json"))
	require.NoError(t, err)
	require.Equal(t, map[string]string{"h1": "prog1", "h2": "prog2"}, b0.Programs)

	// Verify bucket 1 contents on disk.
	b1, err := osutil.ReadJSON[syzspec.CorpusProgramBucket](filepath.Join(dir, "bucket_001.json"))
	require.NoError(t, err)
	require.Equal(t, map[string]string{"h3": "large_prog_exceeding_bucket_limit"}, b1.Programs)
}

func TestIncrementalIndexBuilder(t *testing.T) {
	builder := newIncrementalIndexBuilder()

	// Add functions, syscalls, and bucket indexes.
	builder.recordProgBucket("h1", "bucket_000.json")
	builder.recordProgBucket("h2", "bucket_000.json")
	builder.recordProgBucket("h3", "bucket_001.json")

	builder.addFunctionProgram("fn1", "h1")
	builder.addFunctionProgram("fn1", "h2")
	// Duplicate hash should be ignored.
	builder.addFunctionProgram("fn1", "h1")

	builder.addSyscallProgram("sys1", "h1")
	builder.addSyscallProgram("sys1", "h3")

	require.Equal(t, []string{"h1", "h2"}, builder.functionMap["fn1"])
	require.Equal(t, []string{"h1", "h3"}, builder.syscallMap["sys1"])
	require.Equal(t, map[string]string{
		"h1": "bucket_000.json",
		"h2": "bucket_000.json",
		"h3": "bucket_001.json",
	}, builder.progToBucket)

	// Verify capping at maxIndexedProgramsPerTarget (50).
	for i := range 60 {
		h := fmt.Sprintf("hash_%02d", i)
		builder.addFunctionProgram("common_fn", h)
	}
	require.Len(t, builder.functionMap["common_fn"], 50)
	require.Equal(t, "hash_00", builder.functionMap["common_fn"][0])
	require.Equal(t, "hash_49", builder.functionMap["common_fn"][49])
}
