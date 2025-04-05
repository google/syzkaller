// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"compress/gzip"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGzipResponseWriterCloser_no_compression(t *testing.T) {
	res := httptest.NewRecorder()
	gz := newGzipResponseWriterCloser(res)
	gz.Write([]byte("test"))

	err := gz.writeResult(httpRequestWithAcceptedEncoding(""))
	assert.NoError(t, err)
	assert.Equal(t, "test", res.Body.String())
	assert.Equal(t, "", res.Header().Get("Content-Encoding"))
}

func TestGzipResponseWriterCloser_with_compression(t *testing.T) {
	res := httptest.NewRecorder()
	gz := newGzipResponseWriterCloser(res)
	gz.Write([]byte("test"))

	err := gz.writeResult(httpRequestWithAcceptedEncoding("gzip"))
	assert.NoError(t, err)
	assert.Equal(t, "gzip", res.Header().Get("Content-Encoding"))

	gr, _ := gzip.NewReader(res.Body)
	gotBytes := make([]byte, 28)
	n, _ := gr.Read(gotBytes)
	gotBytes = gotBytes[:n]
	assert.Equal(t, "test", string(gotBytes))
}

func TestGzipResponseWriterCloser_headers(t *testing.T) {
	res := httptest.NewRecorder()
	gz := newGzipResponseWriterCloser(res)

	gz.Header().Add("key", "val1")
	gz.Header().Add("key", "val2")
	err := gz.writeResult(httpRequestWithAcceptedEncoding(""))
	assert.NoError(t, err)
	assert.Equal(t, http.Header{
		"Key": []string{"val1", "val2"},
	}, res.Header())
}

func TestGzipResponseWriterCloser_status(t *testing.T) {
	res := httptest.NewRecorder()
	gz := newGzipResponseWriterCloser(res)

	gz.WriteHeader(333)
	gz.writeResult(httpRequestWithAcceptedEncoding("gzip"))
	assert.Equal(t, 333, res.Code)
}

func httpRequestWithAcceptedEncoding(encoding string) *http.Request {
	return &http.Request{Header: http.Header{"Accept-Encoding": []string{encoding}}}
}
