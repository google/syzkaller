// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package aflow

import (
	"bytes"
	"encoding/json"
)

// DecodeJSONMap decodes JSON into map[string]any preserving integer precision
// by storing numbers as json.Number instead of float64.
func DecodeJSONMap(data []byte) (map[string]any, error) {
	var m map[string]any
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&m); err != nil {
		return nil, err
	}
	return m, nil
}
