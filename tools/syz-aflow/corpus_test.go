// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/aflow/trajectory"
	"github.com/google/syzkaller/pkg/db"
	"github.com/stretchr/testify/require"
)

func TestCorpusWriter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "corpus.db")
	w, err := openCorpus(path)
	require.NoError(t, err)
	inputs := map[string]any{"TargetOS": "linux", "TargetArch": "amd64"}
	span := func(text string, finished bool) *trajectory.Span {
		span := &trajectory.Span{
			Artifacts: map[trajectory.ArtifactType]string{trajectory.ArtifactSyzProg: text},
		}
		if finished {
			span.Finished = time.Now()
		}
		return span
	}
	// Call properties are dropped, so these two are the same program.
	require.NoError(t, w.saveSpan(inputs, span("getpid() (fail_nth: 1)\n", true)))
	require.NoError(t, w.saveSpan(inputs, span("getpid()\n", true)))
	require.NoError(t, w.saveSpan(inputs, span("gettid()\n", false)))
	// Programs that fail to parse are skipped.
	require.NoError(t, w.saveSpan(inputs, span("no_such_syscall()\n", true)))
	require.NoError(t, w.saveSpan(inputs, &trajectory.Span{Finished: time.Now()}))

	corpusDB, err := db.Open(path, false)
	require.NoError(t, err)
	var progs []string
	for _, rec := range corpusDB.Records {
		progs = append(progs, string(rec.Val))
	}
	require.Equal(t, []string{"getpid()\n"}, progs)
}
