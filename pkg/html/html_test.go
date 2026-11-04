// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package html

import (
	"html/template"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFormatRepro(t *testing.T) {
	tests := []struct {
		hasC   bool
		hasSyz bool
		want   string
	}{
		{false, false, ""},
		{false, true, "syz"},
		{true, false, "C"},
		{true, true, "syz, C"},
	}
	for _, tc := range tests {
		got := formatRepro(tc.hasC, tc.hasSyz)
		require.Equal(t, tc.want, got, "formatRepro(%t, %t)", tc.hasC, tc.hasSyz)
	}
}

func TestLink(t *testing.T) {
	tests := []struct {
		url  string
		text string
		want string
	}{
		{"", "text", "text"},
		{"/bug?id=1&x=2", "a<b", `<a href="/bug?id=1&amp;x=2">a&lt;b</a>`},
		// The url may come from an email (e.g. the Google Groups discussion link).
		{`/x" onclick="alert(1)`, "a", `<a href="/x&#34; onclick=&#34;alert(1)">a</a>`},
	}
	for _, tc := range tests {
		got := link(tc.url, tc.text)
		require.Equal(t, template.HTML(tc.want), got, "link(%q, %q)", tc.url, tc.text)
	}
}
