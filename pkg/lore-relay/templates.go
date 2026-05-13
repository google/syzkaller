// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package lorerelay

import (
	"bytes"
	"embed"
	"fmt"
	"strings"
	"text/template"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/aflow/ai"
	"github.com/google/syzkaller/pkg/email"
)

//go:embed templates/*.txt
var templatesFS embed.FS

// TemplateData holds data for rendering email templates.
type TemplateData struct {
	Patch       *dashapi.NewReportResult
	Replies     []*dashapi.ReplyResult
	DocsLink    string
	CanUpstream bool
}

func renderTemplate(name, tmplStr string, data TemplateData) (string, error) {
	t, err := template.New(name).Funcs(template.FuncMap{
		"quote": quote,
	}).Parse(tmplStr)
	if err != nil {
		return "", fmt.Errorf("failed to parse template: %w", err)
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("failed to execute template: %w", err)
	}
	return buf.String(), nil
}

// RenderBody renders the email body based on the poll result.
func RenderBody(cfg *Config, res *dashapi.ReportPollResult) (string, error) {
	data := TemplateData{
		DocsLink:    cfg.DocsLink,
		CanUpstream: res.CanUpstream,
	}
	if res.Patch != nil {
		var recipients []ai.Recipient
		if res.CanUpstream {
			for _, to := range res.Patch.To {
				recipients = append(recipients, ai.Recipient{Email: to, To: true})
			}
			for _, cc := range res.Patch.Cc {
				recipients = append(recipients, ai.Recipient{Email: cc, To: false})
			}
		}
		// TODO: Figure out what Authors we want to use here.
		res.Patch.Body = strings.TrimSpace(email.FormatPatchDescription(
			res.Patch.Body, email.PatchTemplateData{
				Fixes:      res.Patch.Fixes,
				Tools:      res.Patch.Tools,
				Recipients: recipients,
				Links:      res.Patch.Links,
				ReportedBy: res.Patch.ReportedBy,
			}))
		data.Patch = res.Patch
		tmpl, err := templatesFS.ReadFile("templates/new_patch.txt")
		if err != nil {
			return "", err
		}
		return renderTemplate("new_patch", string(tmpl), data)
	}
	if len(res.Replies) > 0 {
		data.Replies = res.Replies
		tmpl, err := templatesFS.ReadFile("templates/replies.txt")
		if err != nil {
			return "", err
		}
		return renderTemplate("replies", string(tmpl), data)
	}
	return "", fmt.Errorf("empty report result")
}

// GenerateSubject generates the email subject based on the poll result.
func GenerateSubject(res *dashapi.ReportPollResult) string {
	if res.Patch == nil {
		if res.ThreadSubject != "" {
			if strings.HasPrefix(strings.ToLower(res.ThreadSubject), "re:") {
				return res.ThreadSubject
			}
			return "Re: " + res.ThreadSubject
		}
		return ""
	}
	prefix := "PATCH"
	if res.CanUpstream {
		prefix += " RFC"
	}
	if res.Patch.Version > 1 {
		prefix += fmt.Sprintf(" v%d", res.Patch.Version)
	}
	return fmt.Sprintf("[%s] %s", prefix, res.Patch.Subject)
}

func quote(s string) string {
	if s == "" {
		return ""
	}
	lines := strings.Split(s, "\n")
	for i, line := range lines {
		lines[i] = "> " + line
	}
	return strings.Join(lines, "\n") + "\n"
}
