// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"testing"

	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/stretchr/testify/assert"
)

func TestPublicWebAddr(t *testing.T) {
	// The auto-detection path depends on the host environment (hostname, GCE metadata),
	// so only the cases that do not reach it are tested here.
	tests := []struct {
		name      string
		http      string
		publicURL string
		want      string
	}{
		{name: "disabled", http: "", publicURL: "", want: ""},
		{name: "disabled-with-public-url", http: "", publicURL: "http://example.com:8080", want: ""},
		{name: "public-url", http: "localhost:1234", publicURL: "http://a.com:80", want: "http://a.com:80"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			cfg := &mgrconfig.Config{HTTP: test.http, HTTPPublicURL: test.publicURL}
			assert.Equal(t, test.want, publicWebAddr(cfg))
		})
	}
}
