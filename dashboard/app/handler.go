// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package dash

import (
	"bytes"
	"fmt"
	"html/template"
	"net/http"
	"strings"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
	"golang.org/x/net/context"
	"google.golang.org/appengine"
	"google.golang.org/appengine/log"
	"google.golang.org/appengine/user"
)

// This file contains common middleware for UI handlers (auth, html templates, etc).

type AccessLevel int

const (
	AccessPublic AccessLevel = iota + 1
	AccessUser
	AccessAdmin
)

type contextHandler func(c context.Context, w http.ResponseWriter, r *http.Request) error

func handlerWrapper(fn contextHandler) http.Handler {
	return handleContext(handleAuth(fn))
}

func handleContext(fn contextHandler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := appengine.NewContext(r)
		if err := fn(c, w, r); err != nil {
			log.Errorf(c, "%v", err)
			w.WriteHeader(http.StatusInternalServerError)
			if err1 := templates.ExecuteTemplate(w, "error.html", err.Error()); err1 != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
		}
	})
}

func handleAuth(fn contextHandler) contextHandler {
	return func(c context.Context, w http.ResponseWriter, r *http.Request) error {
		if accessLevel(c, r) == AccessPublic {
			u := user.Current(c)
			if u == nil {
				return fmt.Errorf("sign-in required")
			}
			log.Errorf(c, "unauthorized user: domain='%v' email='%v'", u.AuthDomain, u.Email)
			return fmt.Errorf("%v is not authorized to view this", u.Email)
		}
		return fn(c, w, r)
	}
}

func accessLevel(c context.Context, r *http.Request) AccessLevel {
	if user.IsAdmin(c) {
		switch r.FormValue("access") {
		case "public":
			return AccessPublic
		case "user":
			return AccessUser
		}
		return AccessAdmin
	}
	u := user.Current(c)
	if u == nil || u.AuthDomain != "gmail.com" || !strings.HasSuffix(u.Email, config.AuthDomain) {
		return AccessPublic
	}
	return AccessUser
}

func serveTemplate(w http.ResponseWriter, name string, data interface{}) error {
	buf := new(bytes.Buffer)
	if err := templates.ExecuteTemplate(buf, name, data); err != nil {
		return err
	}
	w.Write(buf.Bytes())
	return nil
}

type uiHeader struct {
}

func commonHeader(c context.Context) (*uiHeader, error) {
	h := &uiHeader{}
	return h, nil
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format("Jan 02 15:04")
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
	case ReproLevelSyz:
		return "syz"
	case ReproLevelC:
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

var (
	templates = template.Must(template.New("").Funcs(templateFuncs).ParseGlob("*.html"))

	templateFuncs = template.FuncMap{
		"formatTime":       formatTime,
		"formatClock":      formatClock,
		"formatDuration":   formatDuration,
		"formatLateness":   formatLateness,
		"formatReproLevel": formatReproLevel,
		"formatStat":       formatStat,
	}
)
