// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package app

import (
	"os"
	"path/filepath"
	"regexp"
	"testing"

	"github.com/google/syzkaller/pkg/html"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestTemplatesCompile(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Errorf("template parsing panicked: %v", r)
		}
	}()
	html.CreateGlob(htmlTemplates, "templates/*.html")
	html.CreateTextGlob(mailTemplatesFS, "templates/mail_*.txt")
}

func TestPostFormsHaveCSRFToken(t *testing.T) {
	files, err := filepath.Glob("templates/*.html")
	require.NoError(t, err)
	require.NotEmpty(t, files)

	postFormRe := regexp.MustCompile(`(?is)<form\b[^>]*\bmethod=["']?post["']?[^>]*>(.*?)</form>`)
	foundForms := 0
	for _, file := range files {
		data, err := os.ReadFile(file)
		require.NoError(t, err)
		matches := postFormRe.FindAllStringSubmatch(string(data), -1)
		for i, m := range matches {
			foundForms++
			assert.Contains(t, m[1], `{{template "csrf_field" `,
				"%s form #%d is missing the csrf_field template", file, i+1)
		}
	}
	assert.NotZero(t, foundForms)
}
