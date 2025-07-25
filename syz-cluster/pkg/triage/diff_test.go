// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package triage

import (
	"testing"

	"github.com/google/syzkaller/syz-cluster/pkg/api"
	"github.com/stretchr/testify/assert"
)

func TestNeedFuzzing(t *testing.T) {
	tests := []struct {
		Name    string
		Patch   string
		Verdict string
	}{
		{
			Name: "source code changes",
			Patch: `diff --git a/a.c b/a.c
index c4bfa5f..7b82a4b 100644
--- a/a.c
+++ b/a.c
@@ -1,2 +1,2 @@
-Old text
+new text`,
			Verdict: "",
		},
		{
			Name: "unrelated changes",
			Patch: `diff --git a/documentation.txt b/documentation.txt
new file mode 100644
index 0000000..e15621b
--- /dev/null
+++ b/documentation.txt
@@ -0,0 +1 @@
+new text file`,
			Verdict: reasonNotAffectsBuild,
		},
		{
			Name: "irrelevant file",
			Patch: `diff --git a/MAINTAINERS b/MAINTAINERS
new file mode 100644
index 0000000..e15621b
--- /dev/null
+++ b/MAINTAINERS
@@ -0,0 +1 @@
+new text file`,
			Verdict: reasonNotAffectsBuild,
		},
	}

	for _, test := range tests {
		t.Run(test.Name, func(t *testing.T) {
			reason := NeedFuzzing(&api.Series{
				Patches: []api.SeriesPatch{
					{
						Body: []byte(test.Patch),
					},
				},
			})
			assert.Equal(t, test.Verdict, reason)
		})
	}
}
