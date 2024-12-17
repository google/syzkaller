// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"log"
	"path/filepath"
	"regexp"
	"time"

	"github.com/google/syzkaller/pkg/email"
	"github.com/google/syzkaller/pkg/email/lore"
	"github.com/google/syzkaller/pkg/vcs"
	"github.com/google/syzkaller/syz-cluster/pkg/app"
	"github.com/google/syzkaller/syz-cluster/pkg/blob"
	"github.com/google/syzkaller/syz-cluster/pkg/db"
)

var flagVerbose = flag.Bool("verbose", false, "enable verbose output")

// TODO: add more.
var archivesToQuery = []string{"linux-wireless", "netfilter-devel"}

func main() {
	flag.Parse()
	ctx := context.Background()
	env, err := app.Environment(ctx)
	if err != nil {
		app.Fatalf("failed to set up environment: %v", err)
	}
	manifest := NewManifestSource(`https://lore.kernel.org`)
	fetcher := &SeriesFetcher{
		gitRepoFolder: `/git-repo`, // Set in deployment.yaml.
		seriesRepo:    db.NewSeriesRepository(env.Spanner),
		blobStorage:   env.BlobStorage,
		manifest:      manifest,
	}
	go manifest.Loop(ctx)

	// On start, look at the last week of messages.
	nextFrom := time.Now().Add(-time.Hour * 24 * 7)
	for {
		oldFrom := nextFrom
		// Then, parse last 30 minutes every 15 minutes.
		nextFrom = time.Now().Add(-time.Minute * 15)
		err := fetcher.Update(ctx, oldFrom)
		if err != nil {
			// TODO: make sure these are alerted.
			log.Print(err)
		}
		time.Sleep(15 * time.Minute)
	}
}

type SeriesFetcher struct {
	gitRepoFolder string
	seriesRepo    *db.SeriesRepository
	blobStorage   blob.Storage
	manifest      *ManifestSource
}

func (sf *SeriesFetcher) Update(ctx context.Context, from time.Time) error {
	log.Printf("querying email threads since %v", from)

	manifest := sf.manifest.Get(ctx)
	if manifest == nil {
		return fmt.Errorf("failed to query the manifest data")
	}
	var list []lore.EmailReader
	for _, name := range archivesToQuery {
		info, ok := manifest[name]
		if !ok {
			return fmt.Errorf("manifest has no info for %q", name)
		}
		url := info.LastEpochURL()
		log.Printf("polling %s", url)

		folderName := sanitizeName(name)
		if folderName == "" {
			return fmt.Errorf("invalid archive name: %q", name)
		}
		gitRepo := vcs.NewLKMLRepo(filepath.Join(sf.gitRepoFolder, folderName))
		// TODO: by querying only the last archive, we risk losing the series that are split between both.
		// But for now let's ignore this possibility.
		_, err := gitRepo.Poll(url, "master")
		if err != nil {
			return fmt.Errorf("failed to poll %q: %w", url, err)
		}
		repoList, err := lore.ReadArchive(gitRepo, from)
		if err != nil {
			return err
		}
		log.Printf("queried %d emails", len(repoList))
		list = append(list, repoList...)
	}

	var emails []*email.Email
	idToReader := map[string]lore.EmailReader{}
	for _, item := range list {
		// TODO: this could be done in several threads.
		email, err := item.Parse(nil, nil)
		if err != nil {
			log.Printf("failed to parse email: %v", err)
			continue
		}
		idToReader[email.MessageID] = item
		emails = append(emails, email)
	}
	log.Printf("extracted: %d", len(list))

	allSeries := lore.PatchSeries(emails)
	log.Printf("collected %d series", len(allSeries))

	for _, series := range allSeries {
		if *flagVerbose {
			logSeries(series)
		}
		err := sf.handleSeries(ctx, series, idToReader)
		if err != nil {
			return err
		}
	}
	return nil
}

func (sf *SeriesFetcher) handleSeries(ctx context.Context, series *lore.Series,
	idToReader map[string]lore.EmailReader) error {
	if series.Corrupted != "" {
		log.Printf("skipping %s because of %q", series.MessageID, series.Corrupted)
		return nil
	}
	first := series.Patches[0]
	date := first.Date
	if date.IsZero() || date.After(time.Now()) {
		// We cannot fully trust dates from the mailing list as some of them are very weird, e.g.
		// https://lore.kernel.org/all/20770915-nolibc-run-user-v1-1-3caec61726dc@weissschuh.net/raw.
		date = time.Now()
	}
	err := sf.seriesRepo.Insert(ctx, &db.Series{
		ExtID: series.MessageID,
		// TODO: set AuthorName?
		AuthorEmail: first.Author,
		Title:       series.Subject,
		Version:     int64(series.Version),
		Link:        "https://lore.kernel.org/all/" + series.MessageID,
		PublishedAt: date,
		// TODO: set Cc.
	}, func() ([]*db.Patch, error) {
		var ret []*db.Patch
		for _, patch := range series.Patches {
			body, err := idToReader[patch.MessageID].Read()
			if err != nil {
				return nil, fmt.Errorf("failed to extract %q: %w", patch.MessageID, err)
			}
			// In case of errors, we will waste some space, but let's ignore it for simplicity.
			// Patches are not super big.
			uri, err := sf.blobStorage.Store(bytes.NewReader(body))
			if err != nil {
				return nil, fmt.Errorf("failed to upload patch body: %w", err)
			}
			ret = append(ret, &db.Patch{
				Seq:     int64(patch.Seq),
				Title:   patch.Subject,
				Link:    "https://lore.kernel.org/all/" + patch.MessageID,
				BodyURI: uri,
			})
		}
		return ret, nil
	})
	if err == db.ErrSeriesExists {
		log.Printf("series %s already exists in the DB", series.MessageID)
		return nil
	}
	log.Printf("series %s saved to the DB", series.MessageID)
	return nil
}

func logSeries(series *lore.Series) {
	log.Printf("series ID=%s Subject=%s Patches=%d Version=%d Corrupted=%q",
		series.MessageID, series.Subject, len(series.Patches), series.Version,
		series.Corrupted)
	for _, m := range series.Patches {
		log.Printf("  #%d ID=%s Subject=%s", m.Seq, m.MessageID, m.Subject)
	}
}

func sanitizeName(str string) string {
	reg, err := regexp.Compile("[^a-zA-Z0-9]+")
	if err != nil {
		return ""
	}
	return reg.ReplaceAllString(str, "")
}
