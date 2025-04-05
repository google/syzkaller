// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package dashapi

import (
	"bytes"
	"testing"
)

func TestNewOpts(t *testing.T) {
	tests := []struct {
		name      string
		userAgent string
	}{
		{
			name: "no_options",
		},
		{
			name:      "custom_user_agent",
			userAgent: "Custom Agent/2.3",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			opts := []DashboardOpts{}
			if test.userAgent != "" {
				opts = append(opts, UserAgent(test.userAgent))
			}
			dash, err := New("some_client", "some_addr", "some_key", opts...)
			if err != nil {
				t.Fatalf("call to New() returned unexpected error, got: %v, want: nil", err)
			}

			req, err := dash.ctor("GET", "http://www.example.com", bytes.NewBuffer([]byte("body")))
			if err != nil {
				t.Errorf("ctor() returned unexpected error, got: %v, want: nil", err)
			}

			got := req.Header.Get("User-Agent")
			if got != test.userAgent {
				t.Errorf("created request has unexpected header. got: %s, want: 'Custom Agent/2.3'", got)
			}
		})
	}
}
