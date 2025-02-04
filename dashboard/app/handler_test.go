// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"compress/gzip"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGzipResponseWriterCloser_no_compression(t *testing.T) {
	gz := newGzipResponseWriterCloser()
	gz.Write([]byte("test"))

	res := httptest.NewRecorder()
	bytesWritten, err := gz.writeResult(res, true)
	assert.NoError(t, err)
	assert.Equal(t, 4, bytesWritten)
	assert.Equal(t, "test", res.Body.String())
	assert.Equal(t, "", res.Header().Get("Content-Encoding"))
}

func TestGzipResponseWriterCloser_with_compression(t *testing.T) {
	gz := newGzipResponseWriterCloser()
	gz.Write([]byte("test"))

	res := httptest.NewRecorder()
	bytesWritten, err := gz.writeResult(res, false)
	assert.NoError(t, err)
	assert.Equal(t, "gzip", res.Header().Get("Content-Encoding"))
	assert.Equal(t, 28, bytesWritten)

	gr, _ := gzip.NewReader(res.Body)
	gotBytes := make([]byte, 28)
	n, _ := gr.Read(gotBytes)
	gotBytes = gotBytes[:n]
	assert.Equal(t, "test", string(gotBytes))
}
