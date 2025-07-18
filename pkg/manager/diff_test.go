// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package manager

import (
	"testing"

	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPatchFocusAreas(t *testing.T) {
	cfg := &mgrconfig.Config{
		KernelSrc: t.TempDir(),
	}
	require.NoError(t, osutil.FillDirectory(cfg.KernelSrc, map[string]string{
		"header.h": `Test`,
		"a.c": `#include <header.h>
int main(void) { }`,
		"b.c": `int main(void) { }`,
		"c.c": `int main(void) { }`,
	}))

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
		// Also, emulate an update to te header.h.
		[]byte(`diff --git a/header.h b/header.h
index 103167d..fbf7a68 100644
--- a/header.h
+++ b/header.h
@@ -1 +1 @@
-Test
\ No newline at end of file
+Test2
\ No newline at end of file`),
	})

	assert.Equal(t, []mgrconfig.FocusArea{
		{
			Name: modifiedArea,
			Filter: mgrconfig.CovFilterCfg{
				Files: []string{"b.c", "header.h"},
			},
			Weight: 3.0,
		},
		{
			Name: includesArea,
			Filter: mgrconfig.CovFilterCfg{
				Files: []string{"a.c"},
			},
			Weight: 2.0,
		},
		{
			Weight: 1.0,
		},
	}, cfg.Experimental.FocusAreas)
}
