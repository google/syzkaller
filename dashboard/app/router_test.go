// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRouterExactMatch(t *testing.T) {
	c := NewCtx(t)
	defer c.Close()

	tests := []struct {
		url      string
		wantCode int
	}{
		{"/", http.StatusFound},
		{"/upstream", http.StatusOK},
		{"/upstream/bug-summaries", http.StatusInternalServerError},
		{"/upstream/graph/coverage/invalid", http.StatusNotFound},
		{"/upstream/invalid_route", http.StatusNotFound},
		{"/upstream/coverage/subsystems", http.StatusNotFound},
		{"/test1/coverage/subsystems", http.StatusTemporaryRedirect},
	}

	for _, tc := range tests {
		req, err := c.inst.NewRequest("GET", tc.url, nil)
		require.NoError(t, err)
		req = registerRequest(req, c)
		req = req.WithContext(c.transformContext(req.Context()))
		rr := httptest.NewRecorder()
		http.DefaultServeMux.ServeHTTP(rr, req)

		status := rr.Code
		require.Equal(t, tc.wantCode, status, "unexpected status code for %s", tc.url)
	}
}
