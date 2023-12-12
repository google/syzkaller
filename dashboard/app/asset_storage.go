// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"errors"
	"fmt"
	"net/http"
	"sort"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/asset"
	"github.com/google/syzkaller/sys/targets"
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
	buildURLs, crashURLs := []string{}, []string{}
	g, _ := errgroup.WithContext(c)
	g.Go(func() error {
		var err error
		buildURLs, err = neededBuildURLs(c)
		return err
	})
	g.Go(func() error {
		var err error
		crashURLs, err = neededCrashURLs(c)
		return err
	})
	if err := g.Wait(); err != nil {
		return nil, err
	}
	return &dashapi.NeededAssetsResp{
		DownloadURLs: append(buildURLs, crashURLs...),
	}, nil
}

// nolint: dupl
func neededBuildURLs(c context.Context) ([]string, error) {
	var builds []*Build
	_, err := db.NewQuery("Build").
		Filter("Assets.DownloadURL>", "").
		Project("Assets.DownloadURL").
		GetAll(c, &builds)
	if err != nil {
		return nil, fmt.Errorf("failed to query builds: %w", err)
	}
	log.Infof(c, "queried %v builds with assets", len(builds))
	ret := []string{}
	for _, build := range builds {
		for _, asset := range build.Assets {
			ret = append(ret, asset.DownloadURL)
		}
	}
	return ret, nil
}

// nolint: dupl
func neededCrashURLs(c context.Context) ([]string, error) {
	var crashes []*Crash
	_, err := db.NewQuery("Crash").
		Filter("Assets.DownloadURL>", "").
		Project("Assets.DownloadURL").
		GetAll(c, &crashes)
	if err != nil {
		return nil, fmt.Errorf("failed to query assets: %w", err)
	}
	log.Infof(c, "queried %v crashes with assets", len(crashes))
	ret := []string{}
	for _, crash := range crashes {
		for _, asset := range crash.Assets {
			ret = append(ret, asset.DownloadURL)
		}
	}
	return ret, nil
}

func handleDeprecateAssets(w http.ResponseWriter, r *http.Request) {
	c := appengine.NewContext(r)
	for ns := range getConfig(c).Namespaces {
		err := deprecateNamespaceAssets(c, ns)
		if err != nil {
			log.Errorf(c, "deprecateNamespaceAssets failed for ns=%v: %v", ns, err)
		}
	}
	err := deprecateCrashAssets(c)
	if err != nil {
		log.Errorf(c, "deprecateCrashAssets failed: %v", err)
	}
}

func deprecateCrashAssets(c context.Context) error {
	ad := crashAssetDeprecator{c: c}
	const crashBatchSize = 16
	return ad.batchProcessCrashes(crashBatchSize)
}

func deprecateNamespaceAssets(c context.Context, ns string) error {
	ad := buildAssetDeprecator{
		ns:         ns,
		c:          c,
		lastBuilds: map[string]*Build{},
	}
	const buildBatchSize = 16
	err := ad.batchProcessBuilds(buildBatchSize)
	if err != nil {
		return fmt.Errorf("build batch processing failed: %w", err)
	}
	return nil
}

type buildAssetDeprecator struct {
	ns           string
	c            context.Context
	bugsQueried  bool
	relevantBugs map[string]bool
	lastBuilds   map[string]*Build
}

const keepAssetsForClosedBugs = time.Hour * 24 * 30

func (ad *buildAssetDeprecator) lastBuild(manager string) (*Build, error) {
	build, ok := ad.lastBuilds[manager]
	if ok {
		return build, nil
	}
	lastBuild, err := lastManagerBuild(ad.c, ad.ns, manager)
	if err != nil {
		return nil, err
	}
	ad.lastBuilds[manager] = lastBuild
	return lastBuild, err
}

func (ad *buildAssetDeprecator) queryBugs() error {
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

func (ad *buildAssetDeprecator) buildArchivePolicy(build *Build, asset *Asset) (bool, error) {
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

func (ad *buildAssetDeprecator) buildBugStatusPolicy(build *Build) (bool, error) {
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
	// If there are no crashes, but it's the latest build, they may still appear.
	lastBuild, err := ad.lastBuild(build.Manager)
	if err != nil {
		return false, nil
	}
	return build.ID == lastBuild.ID, nil
}

func (ad *buildAssetDeprecator) needThisBuildAsset(build *Build, buildAsset *Asset) (bool, error) {
	// If the asset is reasonably new, we always keep it.
	const alwaysKeepPeriod = time.Hour * 24 * 14
	if buildAsset.CreateDate.After(timeNow(ad.c).Add(-alwaysKeepPeriod)) {
		return true, nil
	}
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

func filterOutAssets(assets []Asset, deleteList []string) []Asset {
	toDelete := map[string]bool{}
	for _, url := range deleteList {
		toDelete[url] = true
	}
	newAssets := []Asset{}
	for _, asset := range assets {
		if _, ok := toDelete[asset.DownloadURL]; !ok {
			newAssets = append(newAssets, asset)
		}
	}
	return newAssets
}

func (ad *buildAssetDeprecator) updateBuild(buildID string, urlsToDelete []string) error {
	tx := func(c context.Context) error {
		build, err := loadBuild(ad.c, ad.ns, buildID)
		if build == nil || err != nil {
			// Assume the DB has been updated in the meanwhile.
			return nil
		}
		build.Assets = filterOutAssets(build.Assets, urlsToDelete)
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

func (ad *buildAssetDeprecator) batchProcessBuilds(count int) error {
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

type crashAssetDeprecator struct {
	c context.Context
}

func (ad *crashAssetDeprecator) batchProcessCrashes(count int) error {
	// Unfortunately we cannot only query the crashes with assets.
	// See the explanation in batchProcessBuilds().
	var crashes []*Crash
	crashKeys, err := db.NewQuery("Crash").
		Order("AssetsLastCheck").
		Limit(count).
		GetAll(ad.c, &crashes)
	if err != nil {
		return fmt.Errorf("failed to fetch crashes: %w", err)
	}
	for i, crash := range crashes {
		toDelete := []string{}
		for _, asset := range crash.Assets {
			needed, err := ad.needThisCrashAsset(crashKeys[i], &asset)
			if err != nil {
				return fmt.Errorf("failed to test crash asset: %w", err)
			} else if !needed {
				toDelete = append(toDelete, asset.DownloadURL)
			}
		}
		if i > 0 {
			// Sleep for one second to prevent the "API error 2 (datastore_v3:
			// CONCURRENT_TRANSACTION): too much contention on these datastore
			// entities. please try again." error.
			time.Sleep(time.Second)
		}
		err := ad.updateCrash(crashKeys[i], toDelete)
		if err != nil {
			return err
		}
	}
	return nil
}

func (ad *crashAssetDeprecator) needThisCrashAsset(crashKey *db.Key, crashAsset *Asset) (bool, error) {
	if crashAsset.Type == dashapi.MountInRepro {
		// We keed mount images from reproducers for as long as the bug is still relevant.
		// They're not that big to set stricter limits.
		return ad.bugStatusPolicy(crashKey, crashAsset)
	}
	return false, fmt.Errorf("no deprecation policy for %s", crashAsset.Type)
}

func (ad *crashAssetDeprecator) bugStatusPolicy(crashKey *db.Key, crashAsset *Asset) (bool, error) {
	bugKey := crashKey.Parent()
	bug := new(Bug)
	err := db.Get(ad.c, bugKey, bug)
	if err != nil {
		return false, fmt.Errorf("failed to query bug: %w", err)
	}
	return bug.Status == BugStatusOpen ||
		bug.Closed.After(timeNow(ad.c).Add(-keepAssetsForClosedBugs)), nil
}

func (ad *crashAssetDeprecator) updateCrash(crashKey *db.Key, urlsToDelete []string) error {
	tx := func(c context.Context) error {
		crash := new(Crash)
		err := db.Get(c, crashKey, crash)
		if err != nil {
			// Assume the DB has been updated in the meanwhile.
			return nil
		}
		crash.Assets = filterOutAssets(crash.Assets, urlsToDelete)
		crash.AssetsLastCheck = timeNow(ad.c)
		if _, err := db.Put(ad.c, crashKey, crash); err != nil {
			return fmt.Errorf("failed to save crash: %w", err)
		}
		return nil
	}
	if err := db.RunInTransaction(ad.c, tx, &db.TransactionOptions{Attempts: 10}); err != nil {
		return fmt.Errorf("failed to update crash: %w", err)
	}
	return nil
}

func queryLatestManagerAssets(c context.Context, ns string, assetType dashapi.AssetType,
	period time.Duration) (map[string]Asset, error) {
	var builds []*Build
	startTime := timeNow(c).Add(-period)
	query := db.NewQuery("Build")
	if ns != "" {
		query = query.Filter("Namespace=", ns)
	}
	_, err := query.Filter("Assets.Type=", assetType).
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

func createAssetList(build *Build, crash *Crash) []dashapi.Asset {
	var crashAssets []Asset
	if crash != nil {
		crashAssets = crash.Assets
	}
	assetList := []dashapi.Asset{}
	for _, reportAsset := range append(build.Assets, crashAssets...) {
		typeDescr := asset.GetTypeDescription(reportAsset.Type)
		if typeDescr == nil || typeDescr.NoReporting {
			continue
		}
		assetList = append(assetList, dashapi.Asset{
			Title:       typeDescr.GetTitle(targets.Get(build.OS, build.Arch)),
			DownloadURL: reportAsset.DownloadURL,
			Type:        reportAsset.Type,
		})
	}
	sort.SliceStable(assetList, func(i, j int) bool {
		return asset.GetTypeDescription(assetList[i].Type).ReportingPrio <
			asset.GetTypeDescription(assetList[j].Type).ReportingPrio
	})
	handleDupAssetTitles(assetList)
	return assetList
}

// Convert asset lists like {"Mounted image", "Mounted image"} to {"Mounted image #1", "Mounted image #2"}.
func handleDupAssetTitles(assetList []dashapi.Asset) {
	duplicates := map[string]bool{}
	for _, asset := range assetList {
		if _, ok := duplicates[asset.Title]; ok {
			duplicates[asset.Title] = true
		} else {
			duplicates[asset.Title] = false
		}
	}
	counts := map[string]int{}
	for i, asset := range assetList {
		if !duplicates[asset.Title] {
			continue
		}
		counts[asset.Title]++
		assetList[i].Title = fmt.Sprintf("%s #%d", asset.Title, counts[asset.Title])
	}
}
