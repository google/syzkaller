// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/asset"
	"golang.org/x/net/context"
	"golang.org/x/sync/errgroup"
	"google.golang.org/appengine/v2"
	db "google.golang.org/appengine/v2/datastore"
	"google.golang.org/appengine/v2/log"
)

// TODO: decide if we want to save job-related assets.

func appendBuildAssets(c context.Context, ns, buildID string, assets []Asset) (*Build, error) {
	var retBuild *Build
	tx := func(c context.Context) error {
		build, err := loadBuild(c, ns, buildID)
		if err != nil {
			return err
		}
		retBuild = build
		appendedOk := false
		var appendErr error
		for _, newAsset := range assets {
			appendErr = build.AppendAsset(newAsset)
			if appendErr == nil {
				appendedOk = true
			}
		}
		// It took quite a number of resources to upload the files, so we return success
		// even if we managed to save at least one of the new assets.
		if !appendedOk {
			return fmt.Errorf("failed to append all assets, last error %w", appendErr)
		}
		if _, err := db.Put(c, buildKey(c, ns, buildID), build); err != nil {
			return fmt.Errorf("failed to put build: %w", err)
		}
		log.Infof(c, "updated build: %#v", build)
		return nil
	}
	if err := db.RunInTransaction(c, tx, &db.TransactionOptions{}); err != nil {
		return nil, err
	}
	return retBuild, nil
}

var ErrAssetDuplicated = errors.New("an asset of this type is already present")

func (build *Build) AppendAsset(addAsset Asset) error {
	typeInfo := asset.GetTypeDescription(addAsset.Type)
	if typeInfo == nil {
		return fmt.Errorf("unknown asset type")
	}
	if !typeInfo.AllowMultiple {
		for _, obj := range build.Assets {
			if obj.Type == addAsset.Type {
				return ErrAssetDuplicated
			}
		}
	}
	build.Assets = append(build.Assets, addAsset)
	return nil
}

func queryNeededAssets(c context.Context) (*dashapi.NeededAssetsResp, error) {
	// So far only build assets.
	var builds []*Build
	_, err := db.NewQuery("Build").
		Filter("Assets.DownloadURL>", "").
		Project("Assets.DownloadURL").
		GetAll(c, &builds)
	if err != nil {
		return nil, fmt.Errorf("failed to query builds: %w", err)
	}
	log.Infof(c, "queried %v builds with assets", len(builds))
	resp := &dashapi.NeededAssetsResp{}
	for _, build := range builds {
		for _, asset := range build.Assets {
			resp.DownloadURLs = append(resp.DownloadURLs, asset.DownloadURL)
		}
	}
	return resp, nil
}

func handleDeprecateAssets(w http.ResponseWriter, r *http.Request) {
	c := appengine.NewContext(r)
	for ns := range config.Namespaces {
		err := deprecateNamespaceAssets(c, ns)
		if err != nil {
			log.Errorf(c, "deprecateNamespaceAssets failed for ns=%v: %v", ns, err)
		}
	}
}

func deprecateNamespaceAssets(c context.Context, ns string) error {
	ad := assetDeprecator{
		ns: ns,
		c:  c,
	}
	const buildBatchSize = 16
	err := ad.batchProcessBuilds(buildBatchSize)
	if err != nil {
		return fmt.Errorf("build batch processing failed: %w", err)
	}
	return nil
}

type assetDeprecator struct {
	ns           string
	c            context.Context
	bugsQueried  bool
	relevantBugs map[string]bool
}

const keepAssetsForClosedBugs = time.Hour * 24 * 30

func (ad *assetDeprecator) queryBugs() error {
	if ad.bugsQueried {
		return nil
	}
	var openBugKeys []*db.Key
	var closedBugKeys []*db.Key
	g, _ := errgroup.WithContext(context.Background())
	g.Go(func() error {
		// Query open bugs.
		var err error
		openBugKeys, err = db.NewQuery("Bug").
			Filter("Namespace=", ad.ns).
			Filter("Status=", BugStatusOpen).
			KeysOnly().
			GetAll(ad.c, nil)
		if err != nil {
			return fmt.Errorf("failed to fetch open builds: %w", err)
		}
		return nil
	})
	g.Go(func() error {
		// Query recently closed bugs.
		var err error
		closedBugKeys, err = db.NewQuery("Bug").
			Filter("Namespace=", ad.ns).
			Filter("Closed>", timeNow(ad.c).Add(-keepAssetsForClosedBugs)).
			KeysOnly().
			GetAll(ad.c, nil)
		if err != nil {
			return fmt.Errorf("failed to fetch closed builds: %w", err)
		}
		return nil
	})
	err := g.Wait()
	if err != nil {
		return fmt.Errorf("failed to query bugs: %w", err)
	}
	ad.relevantBugs = map[string]bool{}
	for _, key := range append(append([]*db.Key{}, openBugKeys...), closedBugKeys...) {
		ad.relevantBugs[key.String()] = true
	}
	return nil
}

func (ad *assetDeprecator) buildArchivePolicy(build *Build, asset *Asset) (bool, error) {
	// If the asset is reasonably new, we always keep it.
	const alwaysKeepPeriod = time.Hour * 24 * 14
	if asset.CreateDate.After(timeNow(ad.c).Add(-alwaysKeepPeriod)) {
		return true, nil
	}
	// Query builds to see whether there's a newer same-type asset on the same week.
	var builds []*Build
	_, err := db.NewQuery("Build").
		Filter("Namespace=", ad.ns).
		Filter("Manager=", build.Manager).
		Filter("Assets.Type=", asset.Type).
		Filter("Assets.CreateDate>", asset.CreateDate).
		Limit(1).
		Order("Assets.CreateDate").
		GetAll(ad.c, &builds)
	if err != nil {
		return false, fmt.Errorf("failed to query newer assets: %w", err)
	}
	log.Infof(ad.c, "running archive policy for %s, date %s; queried %d builds",
		asset.DownloadURL, asset.CreateDate, len(builds))
	sameWeek := false
	if len(builds) > 0 {
		origY, origW := asset.CreateDate.ISOWeek()
		for _, nextAsset := range builds[0].Assets {
			if nextAsset.Type != asset.Type {
				continue
			}
			if nextAsset.CreateDate.Before(asset.CreateDate) ||
				nextAsset.CreateDate.Equal(asset.CreateDate) {
				continue
			}
			nextY, nextW := nextAsset.CreateDate.ISOWeek()
			if origY == nextY && origW == nextW {
				log.Infof(ad.c, "found a newer asset: %s, date %s",
					nextAsset.DownloadURL, nextAsset.CreateDate)
				sameWeek = true
				break
			}
		}
	}
	return !sameWeek, nil
}

func (ad *assetDeprecator) buildBugStatusPolicy(build *Build) (bool, error) {
	if err := ad.queryBugs(); err != nil {
		return false, fmt.Errorf("failed to query bugs: %w", err)
	}
	keys, err := db.NewQuery("Crash").
		Filter("BuildID=", build.ID).
		KeysOnly().
		GetAll(ad.c, nil)
	if err != nil {
		return false, fmt.Errorf("failed to query crashes: %w", err)
	}
	for _, key := range keys {
		bugKey := key.Parent()
		if _, ok := ad.relevantBugs[bugKey.String()]; ok {
			// At least one crash is related to an opened/recently closed bug.
			return true, nil
		}
	}
	return false, nil
}

func (ad *assetDeprecator) needThisBuildAsset(build *Build, buildAsset *Asset) (bool, error) {
	if buildAsset.Type == dashapi.HTMLCoverageReport {
		// We want to keep coverage reports forever, not just
		// while there are any open bugs. But we don't want to
		// keep all coverage reports, just a share of them.
		return ad.buildArchivePolicy(build, buildAsset)
	}
	if build.Type == BuildNormal || build.Type == BuildFailed {
		// A build-related asset, keep it only while there are open bugs with crashes
		// related to this build.
		return ad.buildBugStatusPolicy(build)
	}
	// TODO: fix this once this is no longer the case.
	return false, fmt.Errorf("job-related assets are not supported yet")
}

func (ad *assetDeprecator) updateBuild(buildID string, urlsToDelete []string) error {
	toDelete := map[string]bool{}
	for _, url := range urlsToDelete {
		toDelete[url] = true
	}
	tx := func(c context.Context) error {
		build, err := loadBuild(ad.c, ad.ns, buildID)
		if build == nil || err != nil {
			// Assume the DB has been updated in the meanwhile.
			return nil
		}
		newAssets := []Asset{}
		for _, asset := range build.Assets {
			if _, ok := toDelete[asset.DownloadURL]; !ok {
				newAssets = append(newAssets, asset)
			}
		}
		build.Assets = newAssets
		build.AssetsLastCheck = timeNow(ad.c)
		if _, err := db.Put(ad.c, buildKey(ad.c, ad.ns, buildID), build); err != nil {
			return fmt.Errorf("failed to save build: %w", err)
		}
		return nil
	}
	if err := db.RunInTransaction(ad.c, tx, nil); err != nil {
		return fmt.Errorf("failed to update build: %w", err)
	}
	return nil
}

func (ad *assetDeprecator) batchProcessBuilds(count int) error {
	// We cannot query only the Build with non-empty Assets array and yet sort
	// by AssetsLastCheck. The datastore returns "The first sort property must
	// be the same as the property to which the inequality filter is applied.
	// In your query the first sort property is AssetsLastCheck but the inequality
	// filter is on Assets.DownloadURL.
	// So we have to omit Filter("Assets.DownloadURL>", ""). here.
	var builds []*Build
	_, err := db.NewQuery("Build").
		Filter("Namespace=", ad.ns).
		Order("AssetsLastCheck").
		Limit(count).
		GetAll(ad.c, &builds)
	if err != nil {
		return fmt.Errorf("failed to fetch builds: %w", err)
	}
	for _, build := range builds {
		toDelete := []string{}
		for _, asset := range build.Assets {
			needed, err := ad.needThisBuildAsset(build, &asset)
			if err != nil {
				return fmt.Errorf("failed to test asset: %w", err)
			} else if !needed {
				toDelete = append(toDelete, asset.DownloadURL)
			}
		}
		err := ad.updateBuild(build.ID, toDelete)
		if err != nil {
			return err
		}
	}
	return nil
}

func queryLatestManagerAssets(c context.Context, ns string, assetType dashapi.AssetType,
	period time.Duration) (map[string]Asset, error) {
	var builds []*Build
	startTime := timeNow(c).Add(-period)
	_, err := db.NewQuery("Build").
		Filter("Namespace=", ns).
		Filter("Assets.Type=", assetType).
		Filter("Assets.CreateDate>", startTime).
		Order("Assets.CreateDate").
		GetAll(c, &builds)
	if err != nil {
		return nil, err
	}
	ret := map[string]Asset{}
	for _, build := range builds {
		for _, asset := range build.Assets {
			if asset.Type != assetType {
				continue
			}
			ret[build.Manager] = asset
		}
	}
	return ret, nil
}
