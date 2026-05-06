// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package report

import (
	"bytes"
	"embed"
	"text/template"

	"github.com/google/syzkaller/syz-cluster/pkg/api"
	"github.com/google/syzkaller/syz-cluster/pkg/app"
)

//go:embed template.txt test_reply_template.txt
var templateFS embed.FS

func Render(rep *api.SessionReport, config *app.EmailConfig) ([]byte, error) {
	tmplName := "template.txt"
	if rep.Type == api.ReportTypePatchTest {
		tmplName = "test_reply_template.txt"
	}
	tmpl, err := template.ParseFS(templateFS, "template.txt", "test_reply_template.txt")
	if err != nil {
		return nil, err
	}
	data := struct {
		Report *api.SessionReport
		Config *app.EmailConfig
	}{
		Report: rep,
		Config: config,
	}
	var buf bytes.Buffer
	if err := tmpl.ExecuteTemplate(&buf, tmplName, data); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
