// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package lorerelay

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var flagWrite = flag.Bool("write_lore_tests", false, "overwrite out.txt files")

func TestRender(t *testing.T) {
	flag.Parse()
	basePath := "testdata"
	files, err := os.ReadDir(basePath)
	if err != nil {
		t.Fatal(err)
	}
	hasTests := false
	for _, file := range files {
		if !strings.HasSuffix(file.Name(), ".in.json") {
			continue
		}
		hasTests = true
		fullName := file.Name()
		name := strings.TrimSuffix(fullName, ".in.json")
		t.Run(name, func(t *testing.T) {
			inPath := filepath.Join(basePath, fullName)
			inputData, err := os.ReadFile(inPath)
			require.NoError(t, err)

			var res dashapi.ReportPollResult
			err = json.Unmarshal(inputData, &res)
			require.NoError(t, err)

			output, err := RenderBody(&Config{DocsLink: "http://docs.link"}, &res)
			require.NoError(t, err)
			subject := GenerateSubject(&res)
			fullOutput := "Subject: " + subject + "\n\n" + output
			outPath := filepath.Join(basePath, name+".out.txt")
			if *flagWrite {
				err := os.WriteFile(outPath, []byte(fullOutput), 0644)
				require.NoError(t, err)
			} else {
				expected, err := os.ReadFile(outPath)
				require.NoError(t, err)
				assert.Equal(t, string(expected), fullOutput)
			}
		})
	}

	require.True(t, hasTests, "no test cases found in %s", basePath)
}
