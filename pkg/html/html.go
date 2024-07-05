// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package html

import (
	"fmt"
	"html/template"
	"net/url"
	"path/filepath"
	"reflect"
	"strings"
	texttemplate "text/template"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/vcs"
	"google.golang.org/appengine/v2"
)

// search path differs for the tests and AppEngine because we don't follow
// the recommended folder structure (my best guess).
// When you run the dashboard/app tests, CWD is syzkaller/dashboard/app.
// When you deploy AppEngine in the GOPATH mode, CWD is syzkaller/dashboard/app.
// When you deploy AppEngine in the  GOMOD, CWD is syzkaller/.
var globSearchPath = func() string {
	if appengine.IsAppEngine() {
		return "dashboard/app/templates/"
	}
	return "templates/"
}()

// SetGlobSearchPath overrides the default path where syzkaller looks for templates.
func SetGlobSearchPath(path string) {
	globSearchPath = path
}

func CreateGlob(glob string) *template.Template {
	if strings.Contains(glob, string(filepath.Separator)) {
		panic("glob can't be a path, the files mask is expected")
	}
	return template.Must(
		template.New("").Funcs(Funcs).ParseGlob(filepath.Join(globSearchPath, glob)))
}

func CreateTextGlob(glob string) *texttemplate.Template {
	if strings.Contains(glob, string(filepath.Separator)) {
		panic("glob can't be a path, the files mask is expected")
	}
	return texttemplate.Must(
		texttemplate.New("").Funcs(Funcs).ParseGlob(filepath.Join(globSearchPath, glob)))
}

var Funcs = template.FuncMap{
	"link":                   link,
	"optlink":                optlink,
	"formatTime":             FormatTime,
	"formatDate":             FormatDate,
	"formatKernelTime":       formatKernelTime,
	"formatJSTime":           formatJSTime,
	"formatClock":            formatClock,
	"formatDuration":         formatDuration,
	"formatLateness":         formatLateness,
	"formatReproLevel":       formatReproLevel,
	"formatStat":             formatStat,
	"formatShortHash":        formatShortHash,
	"formatTagHash":          formatTagHash,
	"formatCommitTableTitle": formatCommitTableTitle,
	"formatList":             formatStringList,
	"selectBisect":           selectBisect,
	"dereference":            dereferencePointer,
	"commitLink":             commitLink,
}

func selectBisect(rep *dashapi.BugReport) *dashapi.BisectResult {
	if rep.BisectFix != nil {
		return rep.BisectFix
	}
	return rep.BisectCause
}

func link(url, text string) template.HTML {
	text = template.HTMLEscapeString(text)
	if url != "" {
		text = fmt.Sprintf(`<a href="%v">%v</a>`, url, text)
	}
	return template.HTML(text)
}

func optlink(url, text string) template.HTML {
	if url == "" {
		return template.HTML("")
	}
	return link(url, text)
}

func FormatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format("2006/01/02 15:04")
}

func FormatDate(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format("2006/01/02")
}

func formatKernelTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	// This is how dates appear in git log.
	return t.Format("Mon Jan 2 15:04:05 2006 -0700")
}

func formatJSTime(t time.Time) string {
	return t.Format("2006-01-02T15:04:05") // ISO 8601 without time zone
}

func formatClock(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format("15:04")
}

func formatDuration(d time.Duration) string {
	if d == 0 {
		return ""
	}
	days := int(d / (24 * time.Hour))
	hours := int(d / time.Hour % 24)
	mins := int(d / time.Minute % 60)
	if days >= 10 {
		return fmt.Sprintf("%vd", days)
	} else if days != 0 {
		return fmt.Sprintf("%vd%02vh", days, hours)
	} else if hours != 0 {
		return fmt.Sprintf("%vh%02vm", hours, mins)
	}
	return fmt.Sprintf("%vm", mins)
}

func formatLateness(now, t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := now.Sub(t)
	if d < 5*time.Minute {
		return "now"
	}
	return formatDuration(d)
}

func formatReproLevel(l dashapi.ReproLevel) string {
	switch l {
	case dashapi.ReproLevelSyz:
		return "syz"
	case dashapi.ReproLevelC:
		return "C"
	default:
		return ""
	}
}

func formatStat(v int64) string {
	if v == 0 {
		return ""
	}
	return fmt.Sprint(v)
}

func formatShortHash(v string) string {
	const hashLen = 8
	if len(v) <= hashLen {
		return v
	}
	return v[:hashLen]
}

func formatTagHash(v string) string {
	// Note: Fixes/References commit tags should include 12-char hash
	// (see Documentation/process/submitting-patches.rst). Don't change this const.
	const hashLen = 12
	if len(v) <= hashLen {
		return v
	}
	return v[:hashLen]
}

func formatCommitTableTitle(v string) string {
	// This function is very specific to how we format tables in text emails.
	// Truncate commit title so that whole line fits into 78 chars.
	const commitTitleLen = 47
	if len(v) <= commitTitleLen {
		return v
	}
	return v[:commitTitleLen-2] + ".."
}

func formatStringList(list []string) string {
	return strings.Join(list, ", ")
}

func dereferencePointer(v interface{}) interface{} {
	reflectValue := reflect.ValueOf(v)
	if !reflectValue.IsNil() && reflectValue.Kind() == reflect.Ptr {
		elem := reflectValue.Elem()
		if elem.CanInterface() {
			return elem.Interface()
		}
	}
	return v
}

func commitLink(repo, commit string) string {
	return vcs.CommitLink(repo, commit)
}

func AmendURL(baseURL, key, value string) string {
	return TransformURL(baseURL, key, func(_ []string) []string {
		if value == "" {
			return nil
		}
		return []string{value}
	})
}

func DropParam(baseURL, key, value string) string {
	return TransformURL(baseURL, key, func(oldValues []string) []string {
		if value == "" {
			return nil
		}
		var newValues []string
		for _, iterVal := range oldValues {
			if iterVal != value {
				newValues = append(newValues, iterVal)
			}
		}
		return newValues
	})
}

func TransformURL(baseURL, key string, f func([]string) []string) string {
	if baseURL == "" {
		return ""
	}
	parsed, err := url.Parse(baseURL)
	if err != nil {
		return ""
	}
	values := parsed.Query()
	ret := f(values[key])
	if len(ret) == 0 {
		values.Del(key)
	} else {
		values[key] = ret
	}
	parsed.RawQuery = values.Encode()
	return parsed.String()
}
