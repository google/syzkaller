// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// +build appengine

package dash

import (
	"fmt"
	"time"

	"appengine"
	ds "appengine/datastore"
	"appengine/memcache"
)

const cachedKey = "cached"

type Cached struct {
	Bugs    []CachedBug
	Found   int64
	Fixed   int64
	Crashed int64
}

type CachedBug struct {
	ID    int64
	Title string
}

func getCached(c appengine.Context) (*Cached, error) {
	cached := new(Cached)
	if _, err := memcache.Gob.Get(c, cachedKey, cached); err == nil {
		return cached, nil
	} else if err != memcache.ErrCacheMiss {
		c.Errorf("failed to get cached object: %v", err)
	}
	cached, err := buildCached(c)
	if err != nil {
		return nil, fmt.Errorf("failed to build cached object: %v", err)
	}
	item := &memcache.Item{
		Key:        cachedKey,
		Object:     cached,
		Expiration: time.Hour,
	}
	if err := memcache.Gob.Set(c, item); err != nil {
		c.Errorf("failed to set cached object: %v", err)
	}
	return cached, nil
}

func dropCached(c appengine.Context) {
	if err := memcache.Delete(c, cachedKey); err != nil && err != memcache.ErrCacheMiss {
		c.Errorf("failed to drop memcache: %v", err)
	}
}

func buildCached(c appengine.Context) (*Cached, error) {
	cached := &Cached{}
	var bugs []*Bug
	var keys []*ds.Key
	var err error
	if keys, err = ds.NewQuery("Bug").Project("Title", "Status").GetAll(c, &bugs); err != nil {
		return nil, fmt.Errorf("failed to fetch bugs: %v", err)
	}
	bugStatus := make(map[int64]int)
	for i, bug := range bugs {
		id := keys[i].IntID()
		bugStatus[id] = bug.Status
		if bug.Status < BugStatusClosed {
			cached.Bugs = append(cached.Bugs, CachedBug{
				ID:    id,
				Title: fmt.Sprintf("%v (%v)", bug.Title, statusToString(bug.Status)),
			})
		}
		switch bug.Status {
		case BugStatusNew, BugStatusReported, BugStatusUnclear, BugStatusClaimed:
			cached.Found++
		case BugStatusFixed, BugStatusClosed:
			cached.Found++
			cached.Fixed++
		case BugStatusDeleted:
		default:
			return nil, fmt.Errorf("unknown status %v", bug.Status)
		}
	}
	var groups []*Group
	if _, err := ds.NewQuery("Group").GetAll(c, &groups); err != nil {
		return nil, fmt.Errorf("failed to fetch crash groups: %v", err)
	}
	for _, group := range groups {
		status, ok := bugStatus[group.Bug]
		if !ok {
			return nil, fmt.Errorf("failed to find bug for crash %v (%v)", group.Title, group.Seq)
		}
		switch status {
		case BugStatusNew, BugStatusReported, BugStatusFixed, BugStatusUnclear, BugStatusClaimed, BugStatusClosed:
			cached.Crashed += group.NumCrashes
		case BugStatusDeleted:
		default:
			return nil, fmt.Errorf("unknown status %v", status)
		}
	}
	return cached, nil
}
