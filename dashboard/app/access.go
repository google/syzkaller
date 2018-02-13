// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package dash

import (
	"fmt"
	"net/http"

	"golang.org/x/net/context"
	"google.golang.org/appengine/datastore"
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

func checkTextAccess(c context.Context, r *http.Request, tag string, id int64) error {
	if accessLevel(c, r) == AccessAdmin {
		return nil
	}
	switch tag {
	default:
		return checkAccessLevel(c, r, AccessAdmin)
	case "Patch", "Error":
		// Only admin sees jobs.
		return checkAccessLevel(c, r, AccessAdmin)
	case "KernelConfig":
		// This is checked based on text namespace.
		return nil
	case "CrashLog":
		return checkCrashTextAccess(c, r, "Log", id)
	case "CrashReport":
		return checkCrashTextAccess(c, r, "Report", id)
	case "ReproSyz":
		return checkCrashTextAccess(c, r, "ReproSyz", id)
	case "ReproC":
		return checkCrashTextAccess(c, r, "ReproC", id)
	}
}

func checkCrashTextAccess(c context.Context, r *http.Request, field string, id int64) error {
	var crashes []*Crash
	keys, err := datastore.NewQuery("Crash").
		Filter(field+"=", id).
		GetAll(c, &crashes)
	if err != nil {
		return fmt.Errorf("failed to query crashes: %v", err)
	}
	if len(crashes) != 1 {
		fmt.Errorf("checkCrashTextAccess: found %v crashes for %v=%v",
			len(crashes), field, id)
	}
	bug := new(Bug)
	if err := datastore.Get(c, keys[0].Parent(), bug); err != nil {
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
