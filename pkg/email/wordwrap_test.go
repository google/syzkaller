// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package email

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestWordWrap(t *testing.T) {
	tests := []struct {
		name  string
		text  string
		width int
		want  string
	}{
		{
			name:  "empty_string",
			text:  "",
			width: 10,
			want:  "",
		},
		{
			name:  "zero_width",
			text:  "abc",
			width: 0,
			want:  "abc", // width=1 effectively, but the single word doesn't break
		},
		{
			name:  "no_wrap",
			text:  "short",
			width: 10,
			want:  "short",
		},
		{
			name:  "simple_wrap",
			text:  "hello world",
			width: 5,
			want: `hello
world`,
		},
		{
			name:  "exact_width",
			text:  "hello world",
			width: 11,
			want:  "hello world",
		},
		{
			name:  "long_word",
			text:  "thisisaverylongword that breaks",
			width: 10,
			want: `thisisaverylongword
that
breaks`,
		},
		{
			name: "reflow_paragraph",
			text: `hello
world
and more words`,
			width: 10,
			want: `hello
world and
more words`,
		},
		{
			name: "reflow_larger_width",
			text: `word
word
word
word`,
			width: 9,
			want: `word word
word word`,
		},
		{
			name: "preserve_blocks",
			text: `hello

world
  indented
  code
- list
  item`,
			width: 10,
			want: `hello

world
  indented
  code
- list
  item`,
		},
		{
			name: "preserve_indentation",
			text: `  - item 1
  - item 2 with long text`,
			width: 10,
			want: `  - item 1
  - item 2
  with
  long
  text`,
		},
		{
			name: "preserve_all_list_markers",
			text: `1. First
2. Second
* Asterisk
+ Plus
> Quote`,
			width: 20,
			want: `1. First
2. Second
* Asterisk
+ Plus
> Quote`,
		},
		{
			name:  "trailing_spaces",
			text:  `hello world   `,
			width: 5,
			want: `hello
world`,
		},
		{
			name:  "tabs_spaces",
			text:  "\thello\tworld\n\t  deeply \t indented",
			width: 10,
			want:  "\thello\n\tworld\n\t  deeply\n\t  indented",
		},
		{
			name:  "preserve_actual_spaces",
			text:  "word    spaced\nmultiple \t tabs",
			width: 25,
			want:  "word    spaced multiple\ntabs",
		},
		{
			name:  "input_ends_with_newline",
			text:  "hello\n",
			width: 5,
			want:  "hello\n",
		},
		{
			name:  "tab_width_calculation",
			text:  "a\tb\tc\td\te",
			width: 9,
			want:  "a\tb\nc\td\ne", // 'a' (1) + '\t' (to 8) + 'b' (9). Next '\t' goes to 16, triggering wrap.
		},
		{
			name:  "visual_width_tabs",
			text:  "123\tword",
			width: 12,
			want:  "123\tword", // '123' (3) + '\t' (align to 8) + 'word' (4) = 12 total visual columns.
		},
		{
			name:  "non_ascii_characters",
			text:  "Привет, мир", // 7 runes + 1 space + 3 runes = 11 runes
			width: 11,
			want:  "Привет, мир", // Bytes (15+1+6=22) would incorrectly wrap.
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := WordWrap(tt.text, tt.width)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestVisualLength(t *testing.T) {
	tests := []struct {
		name string
		p    int
		s    string
		want int
	}{
		{"empty", 0, "", 0},
		{"simple", 0, "abc", 3},
		{"start_tab", 0, "\t", 8},
		{"offset_tab", 3, "\t", 8},
		{"offset_tab2", 7, "\t", 8},
		{"offset_tab3", 8, "\t", 16},
		{"mixed", 0, "a\tb\tc", 17}, // 'a' (1) + '\t' (8) + 'b' (9) + '\t' (16) + 'c' (17)
		{"p_mixed", 5, " \t ", 9},   // 5 + ' ' (6) + '\t' (to 8) + ' ' (9)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := visualLength(tt.p, tt.s)
			require.Equal(t, tt.want, got)
		})
	}
}
