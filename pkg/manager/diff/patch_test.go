// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package diff

import (
	"fmt"
	"testing"

	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/stretchr/testify/assert"
)

func TestPatchFocusAreas(t *testing.T) {
	cfg := &mgrconfig.Config{}

	baseHashes, patchedHashes := dummySymbolHashes(), dummySymbolHashes()
	baseHashes["function"] = "hash1"
	patchedHashes["function"] = "hash2"

	PatchFocusAreas(cfg, [][]byte{
		[]byte(`diff --git a/b.c b/b.c
index 103167d..fbf7a68 100644
--- a/b.c
+++ b/b.c
@@ -1 +1 @@
-int main(void) { }
\ No newline at end of file
+int main(void) { return 1; }
\ No newline at end of file`),
		// Also, emulate an update to header.h.
		[]byte(`diff --git a/header.h b/header.h
index 103167d..fbf7a68 100644
--- a/header.h
+++ b/header.h
@@ -1 +1 @@
-Test
\ No newline at end of file
+Test2
\ No newline at end of file`),
	}, baseHashes, patchedHashes)

	assert.Equal(t, []mgrconfig.FocusArea{
		{
			Name: symbolsArea,
			Filter: mgrconfig.CovFilterCfg{
				Functions: []string{"^function$"},
			},
			Weight: 6.0,
		},
		{
			Name: filesArea,
			Filter: mgrconfig.CovFilterCfg{
				Files: []string{"b.c", "header.h"},
			},
			Weight: 3.0,
		},
		{
			Weight: 1.0,
		},
	}, cfg.Experimental.FocusAreas)
}

func dummySymbolHashes() map[string]string {
	ret := map[string]string{}
	for i := range 100 {
		ret[fmt.Sprint(i)] = fmt.Sprint(i)
	}
	return ret
}

func TestModifiedSymbols(t *testing.T) {
	t.Run("too many changed", func(t *testing.T) {
		ret := modifiedSymbols(map[string]string{
			"functionA": "hash1",
			"functionB": "hash2",
		}, map[string]string{
			"functionA": "hash1",
			"functionB": "hash is not hash2",
		})
		assert.Empty(t, ret)
	})
	t.Run("less than threshold", func(t *testing.T) {
		base, patched := dummySymbolHashes(), dummySymbolHashes()
		base["function"] = "hash1"
		patched["function"] = "hash2"
		base["function2"] = "hash1"
		patched["function2"] = "hash2"
		assert.Equal(t, []string{"function", "function2"}, modifiedSymbols(base, patched))
	})
}
