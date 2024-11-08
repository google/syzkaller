// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package pages

import (
	"bytes"
	_ "embed"
	"fmt"
	"html/template"

	"github.com/google/syzkaller/pkg/stat"
)

func StatsHTML() (template.HTML, error) {
	buf := new(bytes.Buffer)
	data := stat.RenderGraphs()
	if err := statsTemplate.Execute(buf, data); err != nil {
		return "", fmt.Errorf("failed to execute stats template: %w", err)
	}
	return template.HTML(buf.String()), nil
}

var statsTemplate = Create(statsHTML)

//go:embed stats.html
var statsHTML string
