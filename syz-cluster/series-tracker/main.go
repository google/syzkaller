// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"maps"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"time"

	"github.com/google/syzkaller/pkg/email"
	"github.com/google/syzkaller/pkg/email/lore"
	"github.com/google/syzkaller/pkg/vcs"
	"github.com/google/syzkaller/syz-cluster/pkg/api"
	"github.com/google/syzkaller/syz-cluster/pkg/app"
)

var (
	flagVerbose = flag.Bool("verbose", false, "enable verbose output")
)

func main() {
	flag.Parse()
	ctx := context.Background()
	manifest := NewManifestSource(`https://lore.kernel.org`)
	fetcher := &SeriesFetcher{
		gitRepoFolder: `/git-repo`, // Set in deployment.yaml.
		client:        app.DefaultClient(),
		manifest:      manifest,
		archives:      archivesToPoll(),
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
			app.Errorf("fetching failed: %v", err)
		}
		time.Sleep(15 * time.Minute)
	}
}

func archivesToPoll() []string {
	cfg, err := app.Config()
	if err != nil {
		app.Fatalf("failed to fetch the config: %v", err)
	}
	if len(cfg.LoreArchives) == 0 {
		app.Fatalf("the list of archives to poll is empty")
	}
	return cfg.LoreArchives
}

type SeriesFetcher struct {
	gitRepoFolder string
	client        *api.Client
	manifest      *ManifestSource
	archives      []string
}

func (sf *SeriesFetcher) Update(ctx context.Context, from time.Time) error {
	log.Printf("querying email threads since %v", from)

	manifest := sf.manifest.Get(ctx)
	if manifest == nil {
		return fmt.Errorf("failed to query the manifest data")
	}
	var list []lore.EmailReader
	for _, name := range sf.archives {
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
			app.Errorf("failed to save the series: %v", err)
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
	apiSeries := &api.Series{
		ExtID:       series.MessageID,
		AuthorEmail: first.Author,
		// TODO: set Cc.
		Title:       series.Subject,
		Version:     series.Version,
		Link:        "https://lore.kernel.org/all/" + series.MessageID,
		PublishedAt: date,
	}
	sp := seriesProcessor{}
	for i, patch := range series.Patches {
		raw, err := idToReader[patch.MessageID].Read()
		if err != nil {
			return fmt.Errorf("failed to extract %q: %w", patch.MessageID, err)
		}
		body, err := sp.Process(raw)
		if err != nil {
			// Fall back to the raw message.
			body = raw
			log.Printf("failed to parse %d: %v", i, err)
		}
		apiSeries.Patches = append(apiSeries.Patches, api.SeriesPatch{
			Seq:   patch.Seq,
			Title: patch.Subject,
			Link:  "https://lore.kernel.org/all/" + patch.MessageID,
			Body:  body,
		})
	}
	apiSeries.Cc = sp.Emails()
	ret, err := sf.client.UploadSeries(ctx, apiSeries)
	if err != nil {
		return fmt.Errorf("failed to save series: %w", err)
	} else if !ret.Saved {
		log.Printf("series %s already exists in the DB", series.MessageID)
		return nil
	}
	_, err = sf.client.UploadSession(ctx, &api.NewSession{
		ExtID: series.MessageID,
	})
	if err != nil {
		return fmt.Errorf("failed to request a fuzzing session: %w", err)
	}
	log.Printf("series %s saved to the DB", series.MessageID)
	return nil
}

type seriesProcessor map[string]struct{}

var errFailedToParse = errors.New("failed to parse the email")

func (sp seriesProcessor) Process(raw []byte) ([]byte, error) {
	msg, err := email.Parse(bytes.NewReader(raw), nil, nil, nil)
	if err != nil {
		return raw, fmt.Errorf("%w: %w", errFailedToParse, err)
	}
	for _, email := range msg.Cc {
		sp[email] = struct{}{}
	}
	return []byte(msg.Body), nil
}

func (sp seriesProcessor) Emails() []string {
	list := slices.Collect(maps.Keys(sp))
	sort.Strings(list)
	return list
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
