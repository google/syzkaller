// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"math/rand"
	"path/filepath"
	"testing"

	"github.com/google/syzkaller/pkg/aflow/trajectory"
	"github.com/google/syzkaller/pkg/db"
	"github.com/google/syzkaller/prog"
	"github.com/google/syzkaller/sys/targets"
	"github.com/stretchr/testify/require"
)

func TestCorpusExporter(t *testing.T) {
	tempDir := t.TempDir()
	corpusPath := filepath.Join(tempDir, "corpus.db")

	target, err := prog.GetTarget(targets.TestOS, targets.TestArch64)
	require.NoError(t, err)

	exporter, err := OpenCorpusExporter(corpusPath)
	require.NoError(t, err)

	ct := target.DefaultChoiceTable()
	rs := rand.New(rand.NewSource(1))
	p1 := target.Generate(rs, 2, ct)
	p1.Calls[0].Props.FailNth = 15
	p1.Calls[0].Props.Async = true
	p1.Calls[1].Props.Rerun = 3

	p2 := target.Generate(rs, 2, ct)

	// Export p1 (with call props set).
	exporter.OnProgram(p1)
	require.Equal(t, 1, len(exporter.db.Records))

	// Re-export p1: should be deduplicated.
	exporter.OnProgram(p1)
	require.Equal(t, 1, len(exporter.db.Records))

	// Export p2.
	exporter.OnProgram(p2)
	require.Equal(t, 2, len(exporter.db.Records))

	// Export program with comment: should be deduplicated with p1 once comments are stripped.
	p1WithComment := p1.Clone()
	p1WithComment.Calls[0].Comment = "test comment"
	exporter.OnProgram(p1WithComment)
	require.Equal(t, 2, len(exporter.db.Records))

	require.NoError(t, exporter.Close())

	// Open the saved corpus.db and inspect the contents.
	corpusDB, err := db.Open(corpusPath, false)
	require.NoError(t, err)
	require.Equal(t, 2, len(corpusDB.Records))

	for _, rec := range corpusDB.Records {
		p, err := target.Deserialize(rec.Val, prog.NonStrict)
		require.NoError(t, err)
		// Ensure fault injection, async, and rerun were stripped from all calls.
		for _, call := range p.Calls {
			require.Equal(t, 0, call.Props.FailNth)
			require.False(t, call.Props.Async)
			require.Equal(t, 0, call.Props.Rerun)
			require.Empty(t, call.Comment)
		}
	}

	// Reopen exporter on the existing corpus.db: should retain seen entries across restarts.
	exporter2, err := OpenCorpusExporter(corpusPath)
	require.NoError(t, err)
	require.Equal(t, 2, len(exporter2.db.Records))
	exporter2.OnProgram(p1) // already seen.
	require.Equal(t, 2, len(exporter2.db.Records))
	require.NoError(t, exporter2.Close())
}

func TestCorpusExporterExportSpans(t *testing.T) {
	tempDir := t.TempDir()
	corpusPath := filepath.Join(tempDir, "corpus.db")
	exporter, err := OpenCorpusExporter(corpusPath)
	require.NoError(t, err)
	defer exporter.Close()

	target, err := prog.GetTarget(targets.TestOS, targets.TestArch64)
	require.NoError(t, err)
	ct := target.DefaultChoiceTable()
	rs := rand.New(rand.NewSource(1))
	p := target.Generate(rs, 2, ct)

	spans := []*trajectory.Span{
		{Type: trajectory.SpanTool, Name: "execute-seed", Args: map[string]any{"ReproSyz": string(p.Serialize())}},
		{Type: trajectory.SpanTool, Name: "execute-seed", Args: map[string]any{"ReproSyz": string(p.Serialize())}},
		{Type: trajectory.SpanTool, Name: "execute-seed", Args: map[string]any{"ReproSyz": "invalid_syntax"}},
	}

	var nilExporter *CorpusExporter
	require.NoError(t, nilExporter.ExportSpans(nil, spans))

	err = exporter.ExportSpans(map[string]any{"TargetOS": "nonexistent_os"}, spans)
	require.Error(t, err)

	inputs := map[string]any{"TargetOS": targets.TestOS, "TargetArch": targets.TestArch64}
	require.NoError(t, exporter.ExportSpans(inputs, spans))
	require.Equal(t, 1, len(exporter.db.Records))
}
