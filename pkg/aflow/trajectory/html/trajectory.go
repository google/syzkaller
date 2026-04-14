// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package html

import (
	"bytes"
	_ "embed"
	"encoding/json"
	"html/template"
	"io"
	"time"

	"github.com/google/syzkaller/pkg/aflow/trajectory"
	"github.com/google/syzkaller/pkg/html"
)

//go:embed report.html
var trajectoryTemplate string

//go:embed trajectory_block.html
var sharedTrajectoryTemplate string

type UIAITrajectorySpan struct {
	Started              time.Time
	Seq                  int64
	Nesting              int64
	Type                 string
	Name                 string
	Model                string
	Duration             time.Duration
	Error                string
	Args                 string
	Results              string
	Instruction          string
	Prompt               string
	Reply                string
	Thoughts             string
	InputTokens          int
	OutputTokens         int
	OutputThoughtsTokens int
}

// RenderReport renders the trajectory spans to the given writer as HTML.
func RenderReport(w io.Writer, spans []*trajectory.Span) error {
	uiSpans := make([]*UIAITrajectorySpan, len(spans))
	for i, span := range spans {
		var duration time.Duration
		if !span.Finished.IsZero() {
			duration = span.Finished.Sub(span.Started)
		}
		uiSpans[i] = &UIAITrajectorySpan{
			Started: span.Started,
			Seq:     int64(span.Seq),
			Nesting: int64(span.Nesting),
			Type:    string(span.Type),
			Name:    span.Name,
			Model:   span.Model,

			Duration:             duration,
			Error:                span.Error,
			Args:                 marshalJSON(span.Args),
			Results:              marshalJSON(span.Results),
			Instruction:          span.Instruction,
			Prompt:               span.Prompt,
			Reply:                span.Reply,
			Thoughts:             span.Thoughts,
			InputTokens:          span.InputTokens,
			OutputTokens:         span.OutputTokens,
			OutputThoughtsTokens: span.OutputThoughtsTokens,
		}
	}

	trajectoryJSON, err := json.Marshal(uiSpans)
	if err != nil {
		return err
	}

	tmpl, err := template.New("trajectory").Funcs(html.Funcs).Parse(trajectoryTemplate)
	if err != nil {
		return err
	}
	// Also parse the shared template.
	tmpl, err = tmpl.Parse(sharedTrajectoryTemplate)
	if err != nil {
		return err
	}

	return tmpl.Execute(w, map[string]any{
		"Trajectory":     uiSpans,
		"TrajectoryJSON": template.JS(trajectoryJSON),
	})
}

// RenderTrajectory renders just the trajectory table and charts as a template.HTML snippet.
func RenderTrajectory(uiSpans []*UIAITrajectorySpan) (template.HTML, error) {
	var buf bytes.Buffer
	trajectoryJSON, err := json.Marshal(uiSpans)
	if err != nil {
		return "", err
	}
	tmpl, err := template.New("snippet").Funcs(html.Funcs).Parse(sharedTrajectoryTemplate)
	if err != nil {
		return "", err
	}
	err = tmpl.ExecuteTemplate(&buf, "ai_trajectory", map[string]any{
		"Trajectory":     uiSpans,
		"TrajectoryJSON": template.JS(trajectoryJSON),
	})
	return template.HTML(buf.String()), err
}

func marshalJSON(v any) string {
	if v == nil {
		return ""
	}
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err.Error()
	}
	return string(b)
}
