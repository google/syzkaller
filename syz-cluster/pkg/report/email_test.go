// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package report

import (
	"encoding/json"
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/syzkaller/syz-cluster/pkg/api"
	"github.com/stretchr/testify/assert"
)

var flagWrite = flag.Bool("write", false, "overwrite out.txt files")

func TestRender(t *testing.T) {
	config := &Config{
		Name:         "syzbot",
		DocsLink:     "http://docs/link",
		SupportEmail: "support@email.com",
	}
	flag.Parse()
	basePath := "testdata"
	files, err := os.ReadDir(basePath)
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		if filepath.Ext(file.Name()) != ".json" {
			continue
		}
		fullName := file.Name()
		name := strings.TrimSuffix(fullName, ".in.json")
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			inPath := filepath.Join(basePath, fullName)
			inputData, err := os.ReadFile(inPath)
			assert.NoError(t, err)

			var report api.SessionReport
			err = json.Unmarshal(inputData, &report)
			assert.NoError(t, err)

			for _, value := range []bool{false, true} {
				report.Moderation = value
				suffix := "upstream"
				if value {
					suffix = "moderation"
				}
				t.Run(suffix, func(t *testing.T) {
					output, err := Render(&report, config)
					assert.NoError(t, err)

					outPath := filepath.Join(basePath, name+"."+suffix+".txt")
					if *flagWrite {
						err := os.WriteFile(outPath, output, 0644)
						assert.NoError(t, err)
					} else {
						expected, err := os.ReadFile(outPath)
						assert.NoError(t, err)
						assert.Equal(t, expected, output)
					}
				})
			}
		})
	}
}
