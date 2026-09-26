// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"cmp"
	"fmt"
	"path/filepath"
	"sync"

	"github.com/google/syzkaller/pkg/aflow/trajectory"
	"github.com/google/syzkaller/pkg/db"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
)

func openCorpus(corpusPath string) (*CorpusExporter, error) {
	if corpusPath == "" {
		return nil, nil
	}
	return OpenCorpusExporter(corpusPath)
}

// CorpusExporter manages a thread-safe corpus.db destination that saves executed
// programs after dropping transient call properties (fault injection, async, rerun)
// and performing deduplication.
type CorpusExporter struct {
	mu sync.Mutex
	db *db.DB
}

func OpenCorpusExporter(path string) (*CorpusExporter, error) {
	if err := osutil.MkdirAll(filepath.Dir(path)); err != nil {
		return nil, fmt.Errorf("failed to create corpus directory: %w", err)
	}
	corpusDB, err := db.Open(path, true)
	if err != nil {
		return nil, fmt.Errorf("failed to open corpus database: %w", err)
	}
	return &CorpusExporter{
		db: corpusDB,
	}, nil
}

func (ce *CorpusExporter) OnProgram(p *prog.Prog) {
	if p == nil || len(p.Calls) == 0 {
		return
	}
	cleaned := p.Clone()
	for _, call := range cleaned.Calls {
		call.Props = prog.CallProps{}
		call.Comment = ""
	}
	data := cleaned.Serialize()
	if len(data) == 0 {
		return
	}
	pHash := hash.String(data)

	ce.mu.Lock()
	defer ce.mu.Unlock()
	ce.db.Save(pHash, data, 0)
}

func (ce *CorpusExporter) Flush() error {
	ce.mu.Lock()
	defer ce.mu.Unlock()
	return ce.db.Flush()
}

func (ce *CorpusExporter) Close() error {
	return ce.Flush()
}

func (ce *CorpusExporter) ExportSpans(inputs map[string]any, spans []*trajectory.Span) error {
	if ce == nil {
		return nil
	}
	target, err := taskTarget(inputs)
	if err != nil {
		return fmt.Errorf("failed to determine target for corpus export: %w", err)
	}
	for _, p := range extractProgramsFromSpans(spans, target) {
		ce.OnProgram(p)
	}
	if err := ce.Flush(); err != nil {
		return fmt.Errorf("failed to flush corpus: %w", err)
	}
	return nil
}

func taskTarget(inputs map[string]any) (*prog.Target, error) {
	os, _ := inputs["TargetOS"].(string)
	arch, _ := inputs["TargetArch"].(string)
	return prog.GetTarget(cmp.Or(os, targets.Linux), cmp.Or(arch, targets.AMD64))
}

func extractProgramsFromSpans(spans []*trajectory.Span, target *prog.Target) []*prog.Prog {
	if target == nil {
		return nil
	}
	var progs []*prog.Prog
	seen := make(map[string]bool)
	for _, span := range spans {
		if span == nil {
			continue
		}
		reproSyz, ok := span.Args["ReproSyz"].(string)
		if !ok || reproSyz == "" || seen[reproSyz] {
			continue
		}
		seen[reproSyz] = true
		p, err := target.Deserialize([]byte(reproSyz), prog.NonStrict)
		if err == nil {
			progs = append(progs, p)
		}
	}
	return progs
}
