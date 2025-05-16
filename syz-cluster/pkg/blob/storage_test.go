// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package blob

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLocalStorage(t *testing.T) {
	storage := NewLocalStorage(t.TempDir())
	var uris []string
	for i := 0; i < 2; i++ {
		uri, err := storage.NewURI()
		require.NoError(t, err)
		content := fmt.Sprintf("object #%d", i)
		err = storage.Write(uri, bytes.NewReader([]byte(content)))
		require.NoError(t, err)
		uris = append(uris, uri)
	}
	for i, uri := range uris {
		readBytes, err := ReadAllBytes(storage, uri)
		require.NoError(t, err)
		assert.EqualValues(t, fmt.Sprintf("object #%d", i), readBytes)
	}
	_, err := storage.Read(localStoragePrefix + "abcdef")
	assert.Error(t, err)
	_, err = storage.Read("abcdef")
	assert.Error(t, err)
}
