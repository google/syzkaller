// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package urlutil

import "net/url"

// SetParam overrides the specific key from the URL.
// It does not take into account that there may be multiple parameters with the same name.
func SetParam(baseURL, key, value string) string {
	return TransformParam(baseURL, key, func(_ []string) []string {
		if value == "" {
			return nil
		}
		return []string{value}
	})
}

// DropParam removes the specific key=value pair from the URL
// (it's possible to have many of parameters with the same name).
// Set value="" to remove the key regardless of the value.
func DropParam(baseURL, key, value string) string {
	return TransformParam(baseURL, key, func(oldValues []string) []string {
		if value == "" {
			return nil
		}
		var newValues []string
		for _, iterVal := range oldValues {
			if iterVal != value {
				newValues = append(newValues, iterVal)
			}
		}
		return newValues
	})
}

// TransformParam is a generic method that transforms the set of values
// for the specified URL parameter key.
func TransformParam(baseURL, key string, f func([]string) []string) string {
	if baseURL == "" {
		return ""
	}
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return ""
	}
	values := parsed.Query()
	ret := f(values[key])
	if len(ret) == 0 {
		values.Del(key)
	} else {
		values[key] = ret
	}
	parsed.RawQuery = values.Encode()
	return parsed.String()
}
