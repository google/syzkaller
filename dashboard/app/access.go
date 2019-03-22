// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package dash

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"golang.org/x/net/context"
	"google.golang.org/appengine"
	db "google.golang.org/appengine/datastore"
	"google.golang.org/appengine/log"
	"google.golang.org/appengine/user"
)

type AccessLevel int

const (
	AccessPublic AccessLevel = iota + 1
	AccessUser
	AccessAdmin
)

func verifyAccessLevel(access AccessLevel) {
	switch access {
	case AccessPublic, AccessUser, AccessAdmin:
		return
	default:
		panic(fmt.Sprintf("bad access level %v", access))
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

func checkTextAccess(c context.Context, r *http.Request, tag string, id int64) (*Crash, error) {
	switch tag {
	default:
		return nil, checkAccessLevel(c, r, AccessAdmin)
	case textPatch:
		return nil, checkJobTextAccess(c, r, "Patch", id)
	case textLog:
		return nil, checkJobTextAccess(c, r, "Log", id)
	case textError:
		return nil, checkJobTextAccess(c, r, "Error", id)
	case textKernelConfig:
		// This is checked based on text namespace.
		return nil, nil
	case textCrashLog:
		// Log and Report can be attached to a Crash or Job.
		crash, err := checkCrashTextAccess(c, r, "Log", id)
		if err == nil || err == ErrAccess {
			return crash, err
		}
		return nil, checkJobTextAccess(c, r, "CrashLog", id)
	case textCrashReport:
		crash, err := checkCrashTextAccess(c, r, "Report", id)
		if err == nil || err == ErrAccess {
			return crash, err
		}
		return nil, checkJobTextAccess(c, r, "CrashReport", id)
	case textReproSyz:
		return checkCrashTextAccess(c, r, "ReproSyz", id)
	case textReproC:
		return checkCrashTextAccess(c, r, "ReproC", id)
	}
}

func checkCrashTextAccess(c context.Context, r *http.Request, field string, id int64) (*Crash, error) {
	var crashes []*Crash
	keys, err := db.NewQuery("Crash").
		Filter(field+"=", id).
		GetAll(c, &crashes)
	if err != nil {
		return nil, fmt.Errorf("failed to query crashes: %v", err)
	}
	if len(crashes) != 1 {
		return nil, fmt.Errorf("checkCrashTextAccess: found %v crashes for %v=%v",
			len(crashes), field, id)
	}
	crash := crashes[0]
	bug := new(Bug)
	if err := db.Get(c, keys[0].Parent(), bug); err != nil {
		return nil, fmt.Errorf("failed to get bug: %v", err)
	}
	bugLevel := bug.sanitizeAccess(accessLevel(c, r))
	return crash, checkAccessLevel(c, r, bugLevel)
}

func checkJobTextAccess(c context.Context, r *http.Request, field string, id int64) error {
	keys, err := db.NewQuery("Job").
		Filter(field+"=", id).
		KeysOnly().
		GetAll(c, nil)
	if err != nil {
		return fmt.Errorf("failed to query jobs: %v", err)
	}
	if len(keys) != 1 {
		return fmt.Errorf("checkJobTextAccess: found %v jobs for %v=%v",
			len(keys), field, id)
	}
	bug := new(Bug)
	if err := db.Get(c, keys[0].Parent(), bug); err != nil {
		return fmt.Errorf("failed to get bug: %v", err)
	}
	bugLevel := bug.sanitizeAccess(accessLevel(c, r))
	return checkAccessLevel(c, r, bugLevel)
}

func (bug *Bug) sanitizeAccess(currentLevel AccessLevel) AccessLevel {
	for ri := len(bug.Reporting) - 1; ri >= 0; ri-- {
		bugReporting := &bug.Reporting[ri]
		if ri == 0 || !bugReporting.Reported.IsZero() {
			ns := config.Namespaces[bug.Namespace]
			bugLevel := ns.ReportingByName(bugReporting.Name).AccessLevel
			if currentLevel < bugLevel {
				if bug.Status == BugStatusFixed || len(bug.Commits) != 0 {
					// Fixed bugs are visible in all reportings,
					// however, without previous reporting private information.
					lastLevel := ns.Reporting[len(ns.Reporting)-1].AccessLevel
					if currentLevel >= lastLevel {
						bugLevel = lastLevel
						sanitizeReporting(bug)
					}
				}
			}
			return bugLevel
		}
	}
	panic("unreachable")
}

func sanitizeReporting(bug *Bug) {
	bug.DupOf = ""
	for ri := range bug.Reporting {
		bugReporting := &bug.Reporting[ri]
		bugReporting.ID = ""
		bugReporting.ExtID = ""
		bugReporting.Link = ""
	}
}
