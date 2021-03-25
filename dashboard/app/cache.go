// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"net/http"
	"time"

	"golang.org/x/net/context"
	"google.golang.org/appengine"
	"google.golang.org/appengine/log"
	"google.golang.org/appengine/memcache"
)

type Cached struct {
	Open    int
	Fixed   int
	Invalid int
}

func CacheGet(c context.Context, r *http.Request, ns string) (*Cached, error) {
	accessLevel := accessLevel(c, r)
	v := new(Cached)
	_, err := memcache.Gob.Get(c, cacheKey(ns, accessLevel), v)
	if err != nil && err != memcache.ErrCacheMiss {
		return nil, err
	}
	if err == nil {
		return v, nil
	}
	bugs, _, err := loadNamespaceBugs(c, ns)
	if err != nil {
		return nil, err
	}
	return buildAndStoreCached(c, bugs, ns, accessLevel)
}

// cacheUpdate updates memcache every hour (called by cron.yaml).
// Cache update is slow and we don't want to slow down user requests.
func cacheUpdate(w http.ResponseWriter, r *http.Request) {
	c := appengine.NewContext(r)
	for ns := range config.Namespaces {
		bugs, _, err := loadNamespaceBugs(c, ns)
		if err != nil {
			log.Errorf(c, "failed load ns=%v bugs: %v", ns, err)
			continue
		}
		for _, accessLevel := range []AccessLevel{AccessPublic, AccessUser, AccessAdmin} {
			_, err := buildAndStoreCached(c, bugs, ns, accessLevel)
			if err != nil {
				log.Errorf(c, "failed to build cached for ns=%v access=%v: %v", ns, accessLevel, err)
				continue
			}
		}
	}
}

func buildAndStoreCached(c context.Context, bugs []*Bug, ns string, accessLevel AccessLevel) (*Cached, error) {
	v := &Cached{}
	for _, bug := range bugs {
		switch bug.Status {
		case BugStatusOpen:
			if accessLevel < bug.sanitizeAccess(accessLevel) {
				continue
			}
			if len(bug.Commits) == 0 {
				v.Open++
			} else {
				v.Fixed++
			}
		case BugStatusFixed:
			v.Fixed++
		case BugStatusInvalid:
			v.Invalid++
		}
	}
	item := &memcache.Item{
		Key:        cacheKey(ns, accessLevel),
		Object:     v,
		Expiration: 4 * time.Hour, // supposed to be updated by cron every hour
	}
	if err := memcache.Gob.Set(c, item); err != nil {
		return nil, err
	}
	return v, nil
}

func cacheKey(ns string, accessLevel AccessLevel) string {
	return fmt.Sprintf("%v-%v", ns, accessLevel)
}
