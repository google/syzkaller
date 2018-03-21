// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package dash

import (
	"bytes"
	"errors"
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

type contextHandler func(c context.Context, w http.ResponseWriter, r *http.Request) error

func handlerWrapper(fn contextHandler) http.Handler {
	return handleContext(handleAuth(fn))
}

func handleContext(fn contextHandler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c := appengine.NewContext(r)
		if err := fn(c, w, r); err != nil {
			if err == ErrAccess {
				w.WriteHeader(http.StatusForbidden)
				loginLink := ""
				if user.Current(c) == nil {
					loginLink, _ = user.LoginURL(c, r.URL.String())
				}
				err1 := templates.ExecuteTemplate(w, "forbidden.html", loginLink)
				if err1 != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
				}
				return
			}
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
		if err := checkAccessLevel(c, r, config.AccessLevel); err != nil {
			return err
		}
		return fn(c, w, r)
	}
}

var ErrAccess = errors.New("unauthorized")

func checkAccessLevel(c context.Context, r *http.Request, level AccessLevel) error {
	if accessLevel(c, r) >= level {
		return nil
	}
	if u := user.Current(c); u != nil {
		// Log only if user is signed in. Not-signed-in users are redirected to login page.
		log.Errorf(c, "unauthorized access: %q [%q] access level %v", u.Email, u.AuthDomain, level)
	}
	return ErrAccess
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
	if u == nil ||
		// devappserver is broken
		u.AuthDomain != "gmail.com" && !appengine.IsDevAppServer() ||
		!strings.HasSuffix(u.Email, config.AuthDomain) {
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
	LoginLink string
}

func commonHeader(c context.Context, r *http.Request) (*uiHeader, error) {
	h := &uiHeader{}
	if user.Current(c) == nil {
		h.LoginLink, _ = user.LoginURL(c, r.URL.String())
	}
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
