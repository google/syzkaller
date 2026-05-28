// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package common

import (
	"embed"
	"testing"

	"github.com/stretchr/testify/require"
)

//go:embed test_prompts/*.md
var testPrompts embed.FS

func TestPrompt(t *testing.T) {
	got := Prompt(testPrompts, "test_prompts/test.md")
	want := `Test prompt.
Don't make assumptions about the kernel source code (it may be different from what you assume it is).
Extensively use the provided code access tools (codesearch-*, git-*, {{.toolGrepper}}, etc)
to examine the actual source code, and confirm any assumptions.`
	require.Equal(t, want, got)
}

func TestPromptEmpty(t *testing.T) {
	require.Panics(t, func() {
		Prompt(testPrompts, "test_prompts/empty.md")
	})
}
