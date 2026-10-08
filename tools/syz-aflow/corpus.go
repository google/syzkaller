// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"log"
	"path/filepath"
	"sync"

	"github.com/google/syzkaller/pkg/aflow/trajectory"
	"github.com/google/syzkaller/pkg/db"
	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/prog"
)

// corpusWriter saves programs executed by workflows into a corpus.db.
// It is shared by all batch tasks, so it's safe for concurrent use.
type corpusWriter struct {
	mu sync.Mutex
	db *db.DB
}

func openCorpus(path string) (*corpusWriter, error) {
	if err := osutil.MkdirAll(filepath.Dir(path)); err != nil {
		return nil, fmt.Errorf("failed to create corpus dir: %w", err)
	}
	corpusDB, err := db.Open(path, true)
	if err != nil {
		return nil, fmt.Errorf("failed to open corpus: %w", err)
	}
	return &corpusWriter{db: corpusDB}, nil
}

// saveSpan saves the program recorded in a finished span, if any.
// Programs that fail to parse are skipped rather than failing the whole batch.
func (w *corpusWriter) saveSpan(inputs map[string]any, span *trajectory.Span) error {
	text := span.Artifacts[trajectory.ArtifactSyzProg]
	if span.Finished.IsZero() || text == "" {
		return nil
	}
	targetOS, _ := inputs["TargetOS"].(string)
	targetArch, _ := inputs["TargetArch"].(string)
	target, err := prog.GetTarget(targetOS, targetArch)
	if err != nil {
		return err
	}
	p, err := target.Deserialize([]byte(text), prog.NonStrict)
	if err != nil {
		log.Printf("skipping program for corpus: failed to parse: %v", err)
		return nil
	}
	return w.save(p)
}

func (w *corpusWriter) save(p *prog.Prog) error {
	// syz-manager rejects corpus programs with fault injection, and the other
	// call properties and comments are not needed in the corpus either.
	for _, call := range p.Calls {
		call.Props = prog.CallProps{}
		call.Comment = ""
	}
	data := p.Serialize()
	w.mu.Lock()
	defer w.mu.Unlock()
	w.db.Save(hash.String(data), data, 0)
	return w.db.Flush()
}
