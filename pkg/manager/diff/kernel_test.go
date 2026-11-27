// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package diff

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/corpus"
	"github.com/google/syzkaller/pkg/db"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSaveCorpus(t *testing.T) {
	file := filepath.Join(t.TempDir(), "corpus.db")
	corpusDB, err := db.Open(file, true)
	require.NoError(t, err)
	// LoadSeeds does this before handing the DB over.
	corpusDB.DiscardData()

	ctx, cancel := context.WithCancel(context.Background())
	kc := &kernelContext{name: "new"}
	updates := make(chan corpus.NewItemEvent)
	done := make(chan struct{})
	go func() {
		kc.saveCorpus(ctx, corpusDB, updates)
		close(done)
	}()
	updates <- corpus.NewItemEvent{Sig: "a", ProgData: []byte("prog a")}
	updates <- corpus.NewItemEvent{Sig: "b", ProgData: []byte("prog b"), Exists: true}
	updates <- corpus.NewItemEvent{Sig: "c", ProgData: []byte("prog c")}
	cancel()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("saveCorpus did not stop on context cancellation")
	}

	// The records must be on disk without any explicit close.
	reopened, err := db.Open(file, false)
	require.NoError(t, err)
	assert.Len(t, reopened.Records, 2)
	assert.Equal(t, []byte("prog a"), reopened.Records["a"].Val)
	assert.Equal(t, []byte("prog c"), reopened.Records["c"].Val)
	assert.NotContains(t, reopened.Records, "b")
}
