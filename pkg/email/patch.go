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

func FormatPatchDescription(description string, tools, authors []string, recipients []ai.Recipient) string {
	buf := new(bytes.Buffer)
	var to, cc []mail.Address
	for _, recipient := range recipients {
		addr := mail.Address{Name: recipient.Name, Address: recipient.Email}
		if recipient.To {
			to = append(to, addr)
		} else {
			cc = append(cc, addr)
		}
	}
	err := patchTemplate.Execute(buf, map[string]any{
		"description": strings.TrimSpace(description),
		"assistedBy":  formatAssistedBy(tools),
		"authors":     authors,
		"to":          to,
		"cc":          cc,
	})
	if err != nil {
		panic(err)
	}
	return buf.String()
}

func FormatPatch(description, diff, baseCommit string, tools, authors []string,
	recipients []ai.Recipient) string {
	return FormatPatchDescription(description, tools, authors, recipients) +
		fmt.Sprintf("%v\nbase-commit: %v\n", diff, baseCommit)
}

// Note: the patches we generate should comply to:
// https://docs.kernel.org/process/coding-assistants.html
var patchTemplate = template.Must(template.New("").Parse(`{{.description}}
{{if .assistedBy}}
Assisted-by: {{.assistedBy}}{{end}}
{{- range $addr := .authors}}
Signed-off-by: {{$addr}}{{end}}
{{- range $addr := .to}}
To: {{$addr.String}}{{end}}
{{- range $addr := .cc}}
Cc: {{$addr.String}}{{end}}

`))

// formatAssistedBy formats models according to the kernel standard.
func formatAssistedBy(tools []string) string {
	slices.Sort(tools)
	slices.Reverse(tools)
	for i, tool := range tools {
		if strings.HasPrefix(tool, "gemini") {
			tools[i] = "Gemini:" + tool
		}
	}
	return strings.Join(tools, " ")
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
