// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package isolated

import (
	"testing"

	"github.com/google/syzkaller/vm/vmimpl"
)

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
		output := vmimpl.EscapeDoubleQuotes(tc.inp)
		if tc.expected != output {
			t.Fatalf("%v: For input %v Expected escaped string %v got %v", i+1, tc.inp, tc.expected, output)
		}
	}
}

func TestSplitTargetPort(t *testing.T) {
	testCases := []struct {
		name       string
		addr       string
		wantTarget string
		wantPort   int
		wantErr    bool
	}{
		{
			name:       "valid with port",
			addr:       "host:123",
			wantTarget: "host",
			wantPort:   123,
			wantErr:    false,
		},
		{
			name:       "valid without port",
			addr:       "host",
			wantTarget: "host",
			wantPort:   22,
			wantErr:    false,
		},
		{
			name:       "empty addr",
			addr:       "",
			wantTarget: "",
			wantPort:   0,
			wantErr:    true,
		},
		{
			name:       "empty target with port",
			addr:       ":123",
			wantTarget: "",
			wantPort:   0,
			wantErr:    true,
		},
		{
			name:       "invalid port",
			addr:       "host:abc",
			wantTarget: "",
			wantPort:   0,
			wantErr:    true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			gotTarget, gotPort, err := splitTargetPort(tc.addr)
			if (err != nil) != tc.wantErr {
				t.Fatalf("splitTargetPort() error = %v, wantErr %v", err, tc.wantErr)
			}
			if gotTarget != tc.wantTarget {
				t.Errorf("splitTargetPort() gotTarget = %v, want %v", gotTarget, tc.wantTarget)
			}
			if gotPort != tc.wantPort {
				t.Errorf("splitTargetPort() gotPort = %v, want %v", gotPort, tc.wantPort)
			}
		})
	}
}
