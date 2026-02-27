// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package crash

import (
	"testing"

	"github.com/google/syzkaller/pkg/aflow"
)

func TestExtractSyzCode(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		wantCode string
	}{
		{
			name:     "raw_code",
			input:    "getpid()\n",
			wantCode: "getpid()",
		},
		{
			name:     "markdown_block",
			input:    "Here is the code:\n```\ngetpid()\n```\n",
			wantCode: "getpid()",
		},
		{
			name:     "syzlang_block",
			input:    "Try this:\n```syzlang\ngetpid()\n```\n",
			wantCode: "getpid()",
		},
		{
			name:     "syzkaller_block",
			input:    "Try this:\n```syzkaller\ngetpid()\n```\n",
			wantCode: "getpid()",
		},
		{
			name:     "chatty_no_block",
			input:    "I think you should use open syscall.",
			wantCode: "I think you should use open syscall.",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			res, err := extractSyzCode(&aflow.Context{}, ExtractSyzCodeArgs{RawSyzlang: test.input})
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if res.CandidateSyzlang != test.wantCode {
				t.Errorf("got code %q, want %q", res.CandidateSyzlang, test.wantCode)
			}
		})
	}
}
