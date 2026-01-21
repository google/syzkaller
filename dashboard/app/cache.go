// Copyright 2020 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/google/syzkaller/pkg/hash"
	"github.com/google/syzkaller/pkg/image"
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

func CacheGet(ctx context.Context, r *http.Request, ns string) (*Cached, error) {
	accessLevel := accessLevel(ctx, r)
	v := new(Cached)
	_, err := memcache.Gob.Get(ctx, cacheKey(ns, accessLevel), v)
	if err != nil && err != memcache.ErrCacheMiss {
		return nil, err
	}
	if err == nil {
		return v, nil
	}
	bugs, _, err := loadNamespaceBugs(ctx, ns)
	if err != nil {
		return nil, err
	}
	backports, err := loadAllBackports(ctx, false)
	if err != nil {
		return nil, err
	}
	return buildAndStoreCached(ctx, bugs, backports, ns, accessLevel)
}

var cacheAccessLevels = []AccessLevel{AccessPublic, AccessUser, AccessAdmin}

// cacheUpdate updates memcache every hour (called by cron.yaml).
// Cache update is slow and we don't want to slow down user requests.
func cacheUpdate(w http.ResponseWriter, r *http.Request) {
	c := appengine.NewContext(r)
	backports, err := loadAllBackports(c, false)
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

func buildAndStoreCached(ctx context.Context, bugs []*Bug, backports []*rawBackport,
	ns string, accessLevel AccessLevel) (*Cached, error) {
	v := &Cached{
		Subsystems: make(map[string]CachedBugStats),
	}
	for _, bug := range bugs {
		if bug.Status == BugStatusOpen && accessLevel < bug.sanitizeAccess(ctx, accessLevel) {
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
		for _, info := range backport.Bugs {
			if accessLevel < info.bug.sanitizeAccess(ctx, accessLevel) {
				continue
			}
			if info.bug.Namespace == ns || outgoing {
				v.MissingBackports++
			}
		}
	}

	item := &memcache.Item{
		Key:        cacheKey(ns, accessLevel),
		Object:     v,
		Expiration: 4 * time.Hour, // supposed to be updated by cron every hour
	}
	if err := memcache.Gob.Set(ctx, item); err != nil {
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

func CachedBugGroups(ctx context.Context, ns string, accessLevel AccessLevel) ([]*uiBugGroup, error) {
	item, err := memcache.Get(ctx, cachedBugGroupsKey(ns, accessLevel))
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

func minuteCacheNsUpdate(ctx context.Context, ns string) error {
	bugs, err := loadVisibleBugs(ctx, ns, nil)
	if err != nil {
		return err
	}
	managers, err := managerList(ctx, ns)
	if err != nil {
		return err
	}
	for _, accessLevel := range cacheAccessLevels {
		groups, err := prepareBugGroups(ctx, bugs, managers, accessLevel, ns)
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
		if err := memcache.Set(ctx, item); err != nil {
			return err
		}
	}
	return nil
}

func CachedManagerList(ctx context.Context, ns string) ([]string, error) {
	return cachedObjectList(ctx,
		fmt.Sprintf("%s-managers-list", ns),
		time.Minute,
		func(ctx context.Context) ([]string, error) {
			return managerList(ctx, ns)
		},
	)
}

func CachedUIManagers(ctx context.Context, accessLevel AccessLevel, ns string,
	filter *userBugFilter) ([]*uiManager, error) {
	return cachedObjectList(ctx,
		fmt.Sprintf("%s-%v-%v-ui-managers", ns, accessLevel, filter.Hash()),
		5*time.Minute,
		func(ctx context.Context) ([]*uiManager, error) {
			return loadManagers(ctx, accessLevel, ns, filter)
		},
	)
}

func cachedObjectList[T any](ctx context.Context, key string, period time.Duration,
	load func(context.Context) ([]T, error)) ([]T, error) {
	// Check if the object is in cache.
	var obj []T
	_, err := memcache.Gob.Get(ctx, key, &obj)
	if err == nil {
		return obj, nil
	} else if err != memcache.ErrCacheMiss {
		return nil, err
	}

	// Load the object.
	obj, err = load(ctx)
	if err != nil {
		return nil, err
	}
	item := &memcache.Item{
		Key:        key,
		Object:     obj,
		Expiration: period,
	}
	if err := memcache.Gob.Set(ctx, item); err != nil {
		return nil, err
	}
	return obj, nil
}

type RequesterInfo struct {
	Requests []time.Time
}

func (ri *RequesterInfo) Record(now time.Time, cfg ThrottleConfig) bool {
	var newRequests []time.Time
	for _, req := range ri.Requests {
		if now.Sub(req) >= cfg.Window {
			continue
		}
		newRequests = append(newRequests, req)
	}
	newRequests = append(newRequests, now)
	sort.Slice(ri.Requests, func(i, j int) bool { return ri.Requests[i].Before(ri.Requests[j]) })
	// Don't store more than needed.
	if len(newRequests) > cfg.Limit+1 {
		newRequests = newRequests[len(newRequests)-(cfg.Limit+1):]
	}
	ri.Requests = newRequests
	// Check that we satisfy the conditions.
	return len(newRequests) <= cfg.Limit
}

var ErrThrottleTooManyRetries = errors.New("all attempts to record request failed")

func ThrottleRequest(ctx context.Context, requesterID string) (bool, error) {
	cfg := getConfig(ctx).Throttle
	if cfg.Empty() || requesterID == "" {
		// No sense to query memcached.
		return true, nil
	}
	key := fmt.Sprintf("requester-%s", hash.String([]byte(requesterID)))
	const attempts = 5
	for i := 0; i < attempts; i++ {
		var obj RequesterInfo
		item, err := memcache.Gob.Get(ctx, key, &obj)
		if err == memcache.ErrCacheMiss {
			ok := obj.Record(timeNow(ctx), cfg)
			err = memcache.Gob.Add(ctx, &memcache.Item{
				Key:        key,
				Object:     obj,
				Expiration: cfg.Window,
			})
			if err == memcache.ErrNotStored {
				// Conflict with another instance. Retry.
				continue
			}
			return ok, err
		} else if err != nil {
			return false, err
		}
		// Update the existing object.
		ok := obj.Record(timeNow(ctx), cfg)
		item.Expiration = cfg.Window
		item.Object = obj
		err = memcache.Gob.CompareAndSwap(ctx, item)
		if err == memcache.ErrCASConflict || err == memcache.ErrNotStored {
			if ok {
				// Only retry if we approved the query.
				// If we denied and there was a concurrent write
				// to the same object, it could have only denied
				// the query as well.
				// Our save won't change anything.
				continue
			}
		} else if err != nil {
			return false, err
		}
		return ok, nil
	}
	return false, ErrThrottleTooManyRetries
}
