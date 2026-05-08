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
	ToolCalls            []string
}

// PopulateToolCalls infers tool calls for each LLM step and associates them
// with the NEXT LLM call at the same Nesting level.
func PopulateToolCalls(uiSpans []*UIAITrajectorySpan) {
	// pendingToolsByNesting maps Nesting level -> list of tool names.
	pendingToolsByNesting := make(map[int64][]string)

	for _, s := range uiSpans {
		switch s.Type {
		case string(trajectory.SpanTool):
			pendingToolsByNesting[s.Nesting] = append(pendingToolsByNesting[s.Nesting], s.Name)
		case string(trajectory.SpanLLM):
			pending := pendingToolsByNesting[s.Nesting]
			if len(pending) > 0 {
				s.ToolCalls = pending
				pendingToolsByNesting[s.Nesting] = nil // Clear.
			}
		}
	}
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

	PopulateToolCalls(uiSpans)
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
	PopulateToolCalls(uiSpans)
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
