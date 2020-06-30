// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"net/http"
	"time"

	"golang.org/x/net/context"
	"google.golang.org/appengine/memcache"
)

type Cached struct {
	Open    int
	Fixed   int
	Invalid int
}

func CacheGet(c context.Context, r *http.Request, ns string) (*Cached, error) {
	accessLevel := accessLevel(c, r)
	key := fmt.Sprintf("%v-%v", ns, accessLevel)
	v := new(Cached)
	_, err := memcache.Gob.Get(c, key, v)
	if err != nil && err != memcache.ErrCacheMiss {
		return nil, err
	}
	if err == nil {
		return v, nil
	}
	if v, err = buildCached(c, ns, accessLevel); err != nil {
		return nil, err
	}
	item := &memcache.Item{
		Key:        key,
		Object:     v,
		Expiration: time.Hour,
	}
	if err := memcache.Gob.Set(c, item); err != nil {
		return nil, err
	}
	return v, nil
}

func buildCached(c context.Context, ns string, accessLevel AccessLevel) (*Cached, error) {
	v := &Cached{}
	bugs, _, err := loadNamespaceBugs(c, ns)
	if err != nil {
		return nil, err
	}
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
	return v, nil
}
