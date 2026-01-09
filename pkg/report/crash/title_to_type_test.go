// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package crash

import (
	"strings"
	"testing"
)

func TestTitleToTypeDefinitions(t *testing.T) {
	knownPrefixes := make(map[string]bool)
	for _, def := range titleToType {
		if len(def.includePrefixes) == 0 {
			t.Errorf("title definition can't be empty")
		}
		for _, prefix := range def.includePrefixes {
			if prefix == "" {
				t.Errorf("title prefix can't be empty")
			}
			if knownPrefixes[prefix] {
				t.Errorf("duplicate title prefix: %q", prefix)
			}
			if wasMatched, byPrefix := hasPrefix(knownPrefixes, prefix); wasMatched {
				t.Errorf("%s was matched by %s", prefix, byPrefix)
			}
			knownPrefixes[prefix] = true
		}
	}
}

func hasPrefix(prefixes map[string]bool, s string) (bool, string) {
	for prefix := range prefixes {
		if strings.HasPrefix(s, prefix) {
			return true, prefix
		}
	}
	return false, ""
}
