// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// syz-backfill-authors fetches missing commit authors from a local git repository
// and uploads them to the dashboard via admin endpoints.
package main

import (
	"bytes"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"path/filepath"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/tool"
	"github.com/google/syzkaller/pkg/vcs"
)

var (
	flagDashboard = flag.String("dashboard", "", "dashboard URL")
	flagToken     = flag.String("token", "", "oauth2 token for admin access (or use gcloud auth print-access-token)")
	flagNamespace = flag.String("namespace", "", "dashboard namespace")
	flagRepo      = flag.String("repo", "", "path to the local git repository")
	flagOS        = flag.String("os", "linux", "OS type of the repository")
	flagCount     = flag.Int("n", 0, "maximum number of authors to update (0 for unlimited)")
	flagVerbose   = flag.Bool("v", false, "enable verbose debug logging")
)

func main() {
	defer tool.Init()()
	if *flagDashboard == "" {
		tool.Failf("missing -dashboard flag")
	}
	if *flagNamespace == "" {
		tool.Failf("missing -namespace flag")
	}
	if *flagRepo == "" {
		tool.Failf("missing -repo flag")
	}
	if *flagToken == "" {
		tool.Failf("missing -token flag")
	}

	repoPath, err := filepath.Abs(*flagRepo)
	if err != nil {
		tool.Failf("failed to get absolute repo path: %v", err)
	}

	repo, err := vcs.NewRepo(*flagOS, "", repoPath, vcs.OptPrecious)
	if err != nil {
		tool.Failf("failed to create repo: %v", err)
	}

	titles, err := fetchMissingTitles()
	if err != nil {
		tool.Failf("failed to fetch missing titles: %v", err)
	}
	if len(titles) == 0 {
		fmt.Printf("no missing author names found in namespace %q\n", *flagNamespace)
		return
	}
	fmt.Printf("found %d commits missing author names\n", len(titles))
	if *flagVerbose {
		for i, title := range titles {
			fmt.Printf("  [%d] Missing author for: %s\n", i, title)
		}
	}

	// Fetch commits without the 5-year age limit.
	commits, missing, err := repo.GetCommitsByTitlesSince(titles, time.Time{})
	if err != nil {
		tool.Failf("failed to fetch commits from local repo: %v", err)
	}

	fmt.Printf("locally found %d commits (missing %d)\n", len(commits), len(missing))
	if *flagVerbose && len(missing) > 0 {
		for i, title := range missing {
			fmt.Printf("  [%d] Could not find locally: %s\n", i, title)
		}
	}

	var dashCommits []dashapi.Commit
	for _, com := range commits {
		// Only upload if we actually found an author name.
		if com.AuthorName != "" {
			dashCommits = append(dashCommits, dashapi.Commit{
				Hash:       com.Hash,
				Title:      com.Title,
				Author:     com.Author,
				AuthorName: com.AuthorName,
				Date:       com.CommitDate,
			})
			if *flagVerbose {
				fmt.Printf("  Found match: '%s' -> Author: '%s', Name: '%s'\n", com.Title, com.Author, com.AuthorName)
			}
		}
	}

	if len(dashCommits) > 0 {
		fmt.Printf("uploading %d commits to dashboard\n", len(dashCommits))
		if err := uploadCommits(dashCommits); err != nil {
			tool.Failf("failed to upload commits: %v", err)
		}
		fmt.Printf("successfully updated %d commits\n", len(dashCommits))
	} else {
		fmt.Printf("no commits with author names found to upload\n")
	}
}

func fetchMissingTitles() ([]string, error) {
	url := fmt.Sprintf("%s/admin/missing_authors?ns=%s", *flagDashboard, *flagNamespace)
	if *flagCount > 0 {
		url += fmt.Sprintf("&limit=%d", *flagCount)
	}
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+*flagToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %v", resp.Status)
	}

	var titles []string
	if err := json.NewDecoder(resp.Body).Decode(&titles); err != nil {
		return nil, err
	}
	return titles, nil
}

func uploadCommits(commits []dashapi.Commit) error {
	data, err := json.Marshal(commits)
	if err != nil {
		return err
	}

	url := fmt.Sprintf("%s/admin/backfill_authors?ns=%s", *flagDashboard, *flagNamespace)
	req, err := http.NewRequest("POST", url, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+*flagToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("unexpected status %v", resp.Status)
	}
	return nil
}
