// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package blob

import (
	"bytes"
	"fmt"
	"io"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestLocalStorage(t *testing.T) {
	storage := NewLocalStorage(t.TempDir())
	var uris []string
	for i := 0; i < 2; i++ {
		content := fmt.Sprintf("object #%d", i)
		uri, err := storage.Store(bytes.NewReader([]byte(content)))
		assert.NoError(t, err)
		uris = append(uris, uri)
	}
	for i, uri := range uris {
		reader, err := storage.Read(uri)
		defer reader.Close()
		assert.NoError(t, err)
		readBytes, err := io.ReadAll(reader)
		assert.NoError(t, err)
		assert.EqualValues(t, fmt.Sprintf("object #%d", i), readBytes)
	}
	_, err := storage.Read(localStoragePrefix + "abcdef")
	assert.Error(t, err)
	_, err = storage.Read("abcdef")
	assert.Error(t, err)
}
