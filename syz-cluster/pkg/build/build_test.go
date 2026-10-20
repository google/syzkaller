// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package build

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	pkgbuild "github.com/google/syzkaller/pkg/build"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadSymbolHashes(t *testing.T) {
	hashes := pkgbuild.SectionHashes{
		Text: map[string]string{"A": "1"},
		Data: map[string]string{"B": "2"},
	}

	jsonData, err := json.Marshal(hashes)
	require.NoError(t, err)

	dir := t.TempDir()
	err = os.WriteFile(filepath.Join(dir, symbolHashesFile), jsonData, 0600)
	require.NoError(t, err)

	fromFile, err := ReadSymbolHashes(dir)
	require.NoError(t, err)
	assert.Equal(t, hashes, fromFile)
}
