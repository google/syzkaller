// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package dash

import (
	"bytes"
	"net/http"

	"github.com/google/syzkaller/pkg/html"
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
			data := &struct {
				Header *uiHeader
				Error  string
			}{
				Header: commonHeader(c, r),
				Error:  err.Error(),
			}
			if err == ErrAccess {
				w.WriteHeader(http.StatusForbidden)
				err1 := templates.ExecuteTemplate(w, "forbidden.html", data)
				if err1 != nil {
					http.Error(w, err.Error(), http.StatusInternalServerError)
				}
				return
			}
			if _, dontlog := err.(ErrDontLog); !dontlog {
				log.Errorf(c, "%v", err)
			}
			w.WriteHeader(http.StatusInternalServerError)
			if err1 := templates.ExecuteTemplate(w, "error.html", data); err1 != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
		}
	})
}

type ErrDontLog error

func handleAuth(fn contextHandler) contextHandler {
	return func(c context.Context, w http.ResponseWriter, r *http.Request) error {
		if err := checkAccessLevel(c, r, config.AccessLevel); err != nil {
			return err
		}
		return fn(c, w, r)
	}
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
	Admin               bool
	LoginLink           string
	AnalyticsTrackingID string
}

func commonHeader(c context.Context, r *http.Request) *uiHeader {
	h := &uiHeader{
		Admin:               accessLevel(c, r) == AccessAdmin,
		AnalyticsTrackingID: config.AnalyticsTrackingID,
	}
	if user.Current(c) == nil {
		h.LoginLink, _ = user.LoginURL(c, r.URL.String())
	}
	return h
}

var templates = html.CreateGlob("*.html")
