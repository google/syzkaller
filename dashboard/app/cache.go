// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/google/syzkaller/pkg/image"
	"golang.org/x/net/context"
	"google.golang.org/appengine/v2"
	"google.golang.org/appengine/v2/log"
	"google.golang.org/appengine/v2/memcache"
)

type Cached struct {
	MissingBackports int
	Total            CachedBugStats
	Subsystems       map[string]CachedBugStats
	NoSubsystem      CachedBugStats
}

type CachedBugStats struct {
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
	backports, err := loadAllBackports(c)
	if err != nil {
		return nil, err
	}
	return buildAndStoreCached(c, bugs, backports, ns, accessLevel)
}

var cacheAccessLevels = []AccessLevel{AccessPublic, AccessUser, AccessAdmin}

// cacheUpdate updates memcache every hour (called by cron.yaml).
// Cache update is slow and we don't want to slow down user requests.
func cacheUpdate(w http.ResponseWriter, r *http.Request) {
	c := appengine.NewContext(r)
	backports, err := loadAllBackports(c)
	if err != nil {
		log.Errorf(c, "failed load backports: %v", err)
		return
	}
	for ns := range getConfig(c).Namespaces {
		bugs, _, err := loadNamespaceBugs(c, ns)
		if err != nil {
			log.Errorf(c, "failed load ns=%v bugs: %v", ns, err)
			continue
		}
		for _, accessLevel := range cacheAccessLevels {
			_, err := buildAndStoreCached(c, bugs, backports, ns, accessLevel)
			if err != nil {
				log.Errorf(c, "failed to build cached for ns=%v access=%v: %v", ns, accessLevel, err)
				continue
			}
		}
	}
}

func buildAndStoreCached(c context.Context, bugs []*Bug, backports []*rawBackport,
	ns string, accessLevel AccessLevel) (*Cached, error) {
	v := &Cached{
		Subsystems: make(map[string]CachedBugStats),
	}
	for _, bug := range bugs {
		if bug.Status == BugStatusOpen && accessLevel < bug.sanitizeAccess(c, accessLevel) {
			continue
		}
		v.Total.Record(bug)
		subsystems := bug.LabelValues(SubsystemLabel)
		for _, label := range subsystems {
			stats := v.Subsystems[label.Value]
			stats.Record(bug)
			v.Subsystems[label.Value] = stats
		}
		if len(subsystems) == 0 {
			v.NoSubsystem.Record(bug)
		}
	}
	for _, backport := range backports {
		outgoing := stringInList(backport.FromNs, ns)
		for _, bug := range backport.Bugs {
			if accessLevel < bug.sanitizeAccess(c, accessLevel) {
				continue
			}
			if bug.Namespace == ns || outgoing {
				v.MissingBackports++
			}
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

func (c *CachedBugStats) Record(bug *Bug) {
	switch bug.Status {
	case BugStatusOpen:
		if len(bug.Commits) == 0 {
			c.Open++
		} else {
			c.Fixed++
		}
	case BugStatusFixed:
		c.Fixed++
	case BugStatusInvalid:
		c.Invalid++
	}
}

func cacheKey(ns string, accessLevel AccessLevel) string {
	return fmt.Sprintf("%v-%v", ns, accessLevel)
}

func CachedBugGroups(c context.Context, ns string, accessLevel AccessLevel) ([]*uiBugGroup, error) {
	item, err := memcache.Get(c, cachedBugGroupsKey(ns, accessLevel))
	if err == memcache.ErrCacheMiss {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	jsonData, destructor := image.MustDecompress(item.Value)
	defer destructor()

	var ret []*uiBugGroup
	err = json.Unmarshal(jsonData, &ret)
	return ret, err
}

func cachedBugGroupsKey(ns string, accessLevel AccessLevel) string {
	return fmt.Sprintf("%v-%v-bug-groups", ns, accessLevel)
}

// minuteCacheUpdate updates memcache every minute (called by cron.yaml).
func handleMinuteCacheUpdate(w http.ResponseWriter, r *http.Request) {
	c := appengine.NewContext(r)
	for ns, nsConfig := range getConfig(c).Namespaces {
		if !nsConfig.CacheUIPages {
			continue
		}
		err := minuteCacheNsUpdate(c, ns)
		if err != nil {
			http.Error(w, fmt.Sprintf("bug groups cache update for %s failed: %v", ns, err),
				http.StatusInternalServerError)
			return
		}
	}
}

func minuteCacheNsUpdate(c context.Context, ns string) error {
	bugs, err := loadVisibleBugs(c, ns, nil)
	if err != nil {
		return err
	}
	managers, err := managerList(c, ns)
	if err != nil {
		return err
	}
	for _, accessLevel := range cacheAccessLevels {
		groups, err := prepareBugGroups(c, bugs, managers, accessLevel, ns)
		if err != nil {
			return fmt.Errorf("failed to fetch groups: %w", err)
		}
		encoded, err := json.Marshal(groups)
		if err != nil {
			return fmt.Errorf("failed to marshal: %w", err)
		}
		item := &memcache.Item{
			Key: cachedBugGroupsKey(ns, accessLevel),
			// The resulting blob can be quite big, so let's compress.
			Value:      image.Compress(encoded),
			Expiration: 2 * time.Minute, // supposed to be updated by cron every minute
		}
		if err := memcache.Set(c, item); err != nil {
			return err
		}
	}
	return nil
}
