// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package config

import (
	"encoding/json"
)

// Unfortunately, if we want to apply a JSON patch to some configuration, we cannot just unmarshal
// it twice - in that case json.RawMessage objects will be completely replaced, but not merged.
func MergeJSONs(left, right []byte) ([]byte, error) {
	vLeft, err := parseFragment(left)
	if err != nil {
		return nil, err
	}
	vRight, err := parseFragment(right)
	if err != nil {
		return nil, err
	}
	return json.Marshal(mergeRecursive(vLeft, vRight))
}

// Recursively apply a patch to a raw JSON data.
// Patch is supposed to be a map, which possibly nests other map objects.
func PatchJSON(left []byte, patch map[string]interface{}) ([]byte, error) {
	vLeft, err := parseFragment(left)
	if err != nil {
		return nil, err
	}
	return json.Marshal(mergeRecursive(vLeft, patch))
}

func parseFragment(input []byte) (parsed interface{}, err error) {
	if len(input) == 0 {
		// For convenience, we allow empty strings to be passed to the function that merges JSONs.
		return
	}
	err = json.Unmarshal(json.RawMessage(input), &parsed)
	return
}

// If one of the elements is not a map, use the new one.
// Otherwise, recursively merge map elements.
func mergeRecursive(left, right interface{}) interface{} {
	if left == nil {
		return right
	}
	if right == nil {
		return left
	}
	mLeft, okLeft := left.(map[string]interface{})
	mRight, okRight := right.(map[string]interface{})
	if !okLeft || !okRight {
		return right
	}
	for key, val := range mRight {
		valLeft, ok := mLeft[key]
		if ok {
			mLeft[key] = mergeRecursive(valLeft, val)
		} else {
			mLeft[key] = val
		}
	}
	return mLeft
}
