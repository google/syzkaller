// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package report

import (
	"bytes"
	"embed"
	"html/template"

	"github.com/google/syzkaller/syz-cluster/pkg/api"
	"github.com/google/syzkaller/syz-cluster/pkg/app"
)

//go:embed template.txt
var templateFS embed.FS

func Render(rep *api.SessionReport, config *app.EmailConfig) ([]byte, error) {
	tmpl, err := template.ParseFS(templateFS, "template.txt")
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
	if err := tmpl.Execute(&buf, data); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}
