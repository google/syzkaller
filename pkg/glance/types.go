// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package glance

import "github.com/google/syzkaller/pkg/clangtool"

type Output struct {
	Functions             []*GlanceFunction `json:"functions,omitempty"`
	Symbols               []*GlanceSymbol   `json:"symbols,omitempty"`
	Includes              []string          `json:"includes,omitempty"`
	MissingCompileCommand string            `json:"missing_compile_command,omitempty"`
}

type GlanceFunction struct {
	Name       string   `json:"name"`
	File       string   `json:"file"`
	StartLine  int      `json:"start_line"`
	EndLine    int      `json:"end_line"`
	Complexity int      `json:"complexity"`
	LocksUsed  []string `json:"locks_used,omitempty"`
	IsExported bool     `json:"is_exported"`
}

// DirSummaryInputs is the input for the directory-level summarization flow.
type DirSummaryInputs struct {
	Dir              string
	FileSummaries    string
	ExportedAPIs     string
	FileDescriptions string
}

// DirSummaryOutputs is the output for the directory-level summarization flow.
type DirSummaryOutputs struct {
	Summary string
}

// Summary represents the final Markdown summary.
type Summary struct {
	Path       string
	SourceHash string
	Body       string
}

type GlanceSymbol struct {
	Name       string `json:"name"`
	Kind       string `json:"kind"`
	Definition string `json:"definition"`
	File       string `json:"file"`
}

func (out *Output) Merge(other *Output, v *clangtool.Verifier) {
	out.Functions = append(out.Functions, other.Functions...)
	out.Symbols = append(out.Symbols, other.Symbols...)
}

func (out *Output) Finalize(v *clangtool.Verifier) {
	out.Functions = clangtool.SortAndDedupSlice(out.Functions)
	out.Symbols = clangtool.SortAndDedupSlice(out.Symbols)
}

func (out *Output) SetSourceFile(file string, updatePath func(string) string) {
	for _, fn := range out.Functions {
		fn.File = updatePath(fn.File)
	}
	for _, sym := range out.Symbols {
		sym.File = updatePath(sym.File)
	}
}
