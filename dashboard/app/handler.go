// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package dash

import (
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
		u := user.Current(c)
		if u == nil {
			return fmt.Errorf("sign-in required")
		}
		if !u.Admin && (u.AuthDomain != "gmail.com" ||
			!strings.HasSuffix(u.Email, config.AuthDomain)) {
			log.Errorf(c, "unauthorized user: domain='%v' email='%v'", u.AuthDomain, u.Email)
			return fmt.Errorf("%v is not authorized to view this", u.Email)
		}
		return fn(c, w, r)
	}
}

type uiHeader struct {
}

func commonHeader(c context.Context) (*uiHeader, error) {
	h := &uiHeader{}
	return h, nil
}

func formatTime(t time.Time) string {
	return t.Format("Jan 02 15:04")
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

var (
	templates = template.Must(template.New("").Funcs(templateFuncs).ParseGlob("*.html"))

	templateFuncs = template.FuncMap{
		"formatTime":       formatTime,
		"formatReproLevel": formatReproLevel,
	}
)
