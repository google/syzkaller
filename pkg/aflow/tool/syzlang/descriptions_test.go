// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package syzlang

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDescriptionFiles(t *testing.T) {
	files := DescriptionFiles()
	require.Greater(t, len(files), 50)
	require.Contains(t, files, "sys.txt")
}

func TestReadDescription(t *testing.T) {
	res, err := readDescription(nil, struct{}{}, readDescArgs{File: "sys.txt"})
	require.NoError(t, err)
	require.Contains(t, res.Output, "meta")

	_, err2 := readDescription(nil, struct{}{}, readDescArgs{File: "non_existent_file.txt"})
	require.Error(t, err2)
}
