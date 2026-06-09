// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package email

import (
	"bufio"
	"bytes"
	"fmt"
	"net/mail"
	"regexp"
	"slices"
	"strings"
	"text/template"

	"github.com/google/syzkaller/pkg/aflow/ai"
)

func ParsePatch(message []byte) (diff string) {
	s := bufio.NewScanner(bytes.NewReader(message))
	diffStarted := false
	for s.Scan() {
		ln := s.Text()
		if lineMatchesDiffStart(ln) {
			diffStarted = true
			diff += ln + "\n"
			continue
		}
		if diffStarted {
			if ln == "--" || ln == "-- " || ln != "" && ln[0] == '>' {
				diffStarted = false
				continue
			}
			if ln == "" || strings.HasPrefix(ln, " ") || strings.HasPrefix(ln, "+") ||
				strings.HasPrefix(ln, "-") || strings.HasPrefix(ln, "@") ||
				strings.HasPrefix(ln, "================") {
				diff += ln + "\n"
				continue
			}
			diffStarted = false
		}
	}
	if diff != "" {
		diff = strings.TrimRight(diff, "\n") + "\n"
	}
	err := s.Err()
	if err == bufio.ErrTooLong {
		// It's a problem of the incoming patch, rather than anything else.
		// Anyway, if a patch contains too long lines, we're probably not
		// interested in it, so let's pretent we didn't see it.
		diff = ""
		return
	} else if err != nil {
		panic("error while scanning from memory: " + err.Error())
	}
	return
}

type PatchTemplateData struct {
	BaseCommit string
	Fixes      ai.FixesTag
	Tools      []string
	Authors    []string
	Recipients []ai.Recipient
	Links      []string
	Closes     []string
	ReportedBy []string

	ReviewedBy []string
	AckedBy    []string
	TestedBy   []string
}

func FormatPatch(description, diff string, data PatchTemplateData) string {
	return FormatPatchDescription(description, data) +
		fmt.Sprintf("%v\nbase-commit: %v\n", diff, data.BaseCommit)
}

func FormatPatchDescription(description string, data PatchTemplateData) string {
	buf := new(bytes.Buffer)
	var to, cc []mail.Address
	for _, recipient := range data.Recipients {
		addr := mail.Address{Name: recipient.Name, Address: recipient.Email}
		if recipient.To {
			to = append(to, addr)
		} else {
			cc = append(cc, addr)
		}
	}
	var fixesStr string
	if data.Fixes.Hash != "" {
		hash := data.Fixes.Hash
		if len(hash) > 12 {
			hash = hash[:12]
		}
		fixesStr = fmt.Sprintf("%v (\"%v\")", hash, data.Fixes.Title)
	}
	err := patchTemplate.Execute(buf, map[string]any{
		"description": strings.TrimSpace(description),
		"fixes":       fixesStr,
		"assistedBy":  formatAssistedBy(data.Tools),
		"authors":     data.Authors,
		"to":          to,
		"cc":          cc,
		"links":       data.Links,
		"closes":      data.Closes,
		"reportedBy":  data.ReportedBy,
		"reviewedBy":  data.ReviewedBy,
		"ackedBy":     data.AckedBy,
		"testedBy":    data.TestedBy,
	})
	if err != nil {
		panic(err)
	}
	return buf.String()
}

// Note: the patches we generate should comply to:
// https://docs.kernel.org/process/coding-assistants.html
var patchTemplate = template.Must(template.New("").Parse(`{{.description}}
{{if .fixes}}
Fixes: {{.fixes}}{{end}}{{if .assistedBy}}
Assisted-by: {{.assistedBy}}{{end}}
{{- range $addr := .reviewedBy}}
Reviewed-by: {{$addr}}{{end}}
{{- range $addr := .ackedBy}}
Acked-by: {{$addr}}{{end}}
{{- range $addr := .testedBy}}
Tested-by: {{$addr}}{{end}}
{{- range $addr := .reportedBy}}
Reported-by: {{$addr}}{{end}}
{{- range $link := .closes}}
Closes: {{$link}}{{end}}
{{- range $link := .links}}
Link: {{$link}}{{end}}
{{- range $addr := .authors}}
Signed-off-by: {{$addr}}{{end}}
{{- range $addr := .to}}
To: {{$addr}}{{end}}
{{- range $addr := .cc}}
Cc: {{$addr}}{{end}}

`))

// formatAssistedBy formats models according to the kernel standard.
func formatAssistedBy(tools []string) string {
	tools = slices.Clone(tools)
	slices.Sort(tools)
	slices.Reverse(tools)
	var res []string
	for _, tool := range tools {
		if strings.HasPrefix(tool, "gemini") {
			tool = "Gemini:" + tool
		}
		if tool != "syzbot" {
			res = append(res, tool)
		}
	}
	res = append(res, "syzbot")
	return strings.Join(res, " ")
}

var diffRegexps = []*regexp.Regexp{
	regexp.MustCompile(`^(---|\+\+\+) [^\s]`),
	regexp.MustCompile(`^diff --git`),
	regexp.MustCompile(`^index [0-9a-f]+\.\.[0-9a-f]+`),
	regexp.MustCompile(`^new file mode [0-9]+`),
	regexp.MustCompile(`^Index: [^\s]`),
}

func lineMatchesDiffStart(ln string) bool {
	for _, re := range diffRegexps {
		if re.MatchString(ln) {
			return true
		}
	}
	return false
}
