// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestDecodeJSONMapPreservesUint64(t *testing.T) {
	const pc = uint64(18446744071636006420)
	data := []byte(`{"PC":18446744071636006420}`)
	m, err := DecodeJSONMap(data)
	require.NoError(t, err)
	require.IsType(t, json.Number(""), m["PC"])

	got, err := convertFromMap[struct {
		PC uint64
	}](m, false, false)
	require.NoError(t, err)
	require.Equal(t, pc, got.PC)
}

func TestConvertFromMapJSONNumber(t *testing.T) {
	const pc = uint64(18446744071636006420)
	testConvertFromMap(t, false, map[string]any{
		"PC": json.Number("18446744071636006420"),
	}, struct {
		PC uint64
	}{
		PC: pc,
	}, "", "")

	testConvertFromMap(t, false, map[string]any{
		"I0": json.Number("-1"),
		"I1": json.Number("2"),
	}, struct {
		I0 int
		I1 int
	}{
		I0: -1,
		I1: 2,
	}, "", "")
}
