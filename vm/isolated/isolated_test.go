// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package isolated

import "testing"

func TestEscapeDoubleQuotes(t *testing.T) {
	testcases := []struct {
		inp      string
		expected string
	}{
		// Input with no quoting returns the same string.
		{
			"",
			"",
		},
		{
			"adsf",
			"adsf",
		},
		// Inputs with escaping of characters other that double
		// quotes returns the same input.
		{
			"\\$\\`\\\\\n", // \$\`\\\n
			"\\$\\`\\\\\n", // \$\`\\\n
		},
		// Input with double quote.
		{
			`"`,
			`\"`,
		},
		// Input with already escaped double quote.
		{
			`\"`,
			`\\\"`,
		},
		// Input with already escaped backtick and already
		// double quote. Should only re-escape the
		// double quote.
		{
			"\\`something\"",   // \`something"
			"\\`something\\\"", // \`something\"
		},
		// Input with already escaped backtick and already
		// escaped double quote. Should only re-escape the
		// escaped double quote.
		{
			"\\`something\\\"",     // \`something\"
			"\\`something\\\\\\\"", // \`something\\\"
		},
		{
			`touch \
    /tmp/OK
touch '/tmp/OK2'
touch "/tmp/OK3"
touch /tmp/OK4
bash -c "bash -c \"ls -al\""`,
			`touch \
    /tmp/OK
touch '/tmp/OK2'
touch \"/tmp/OK3\"
touch /tmp/OK4
bash -c \"bash -c \\\"ls -al\\\"\"`,
		},
	}
	for i, tc := range testcases {
		output := escapeDoubleQuotes(tc.inp)
		if tc.expected != output {
			t.Fatalf("%v: For input %v Expected escaped string %v got %v", i+1, tc.inp, tc.expected, output)
		}
	}
}
