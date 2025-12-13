// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"time"

	"cloud.google.com/go/civil"
	"github.com/google/syzkaller/dashboard/api"
	"github.com/google/syzkaller/pkg/cover"
	"github.com/google/syzkaller/pkg/coveragedb"
)

func getExtAPIDescrForBug(bug *uiBugDetails) *api.Bug {
	return &api.Bug{
		Version:    api.Version,
		Title:      bug.Title,
		ID:         bug.ID,
		Status:     bug.Status,
		FirstCrash: bug.FirstTime,
		LastCrash:  bug.LastTime,
		FixTime: func() *time.Time {
			if bug.FixTime.IsZero() {
				return nil
			}
			return &bug.FixTime
		}(),
		CloseTime: func() *time.Time {
			if bug.ClosedTime.IsZero() {
				return nil
			}
			return &bug.ClosedTime
		}(),
		Discussions: func() []string {
			if bug.ExternalLink == "" {
				return nil
			}
			return []string{bug.ExternalLink}
		}(),
		FixCommits: getBugFixCommits(bug.uiBug),
		CauseCommit: func() *api.Commit {
			bisectCause := bug.BisectCauseJob
			if bisectCause == nil || bisectCause.Commit == nil {
				return nil
			}
			commit := &api.Commit{
				Title:  bisectCause.Commit.Title,
				Link:   bisectCause.Commit.Link,
				Hash:   bisectCause.Commit.Hash,
				Repo:   bisectCause.KernelRepo,
				Branch: bisectCause.KernelBranch,
			}
			if !bisectCause.Commit.Date.IsZero() {
				commit.Date = &bisectCause.Commit.Date
			}
			return commit
		}(),
		Crashes: func() []api.Crash {
			var res []api.Crash
			for _, crash := range bug.Crashes {
				res = append(res, api.Crash{
					Title:              crash.Title,
					SyzReproducerLink:  crash.ReproSyzLink,
					CReproducerLink:    crash.ReproCLink,
					KernelConfigLink:   crash.KernelConfigLink,
					KernelSourceGit:    crash.KernelCommitLink,
					KernelSourceCommit: crash.KernelCommit,
					SyzkallerGit:       crash.SyzkallerCommitLink,
					SyzkallerCommit:    crash.SyzkallerCommit,
					// TODO: add the CompilerDescription
					// TODO: add the Architecture
					CrashReportLink: crash.ReportLink,
				})
			}
			return res
		}(),
	}
}

func getBugFixCommits(bug *uiBug) []api.Commit {
	var res []api.Commit
	for _, commit := range bug.Commits {
		apiCommit := api.Commit{
			Title:  commit.Title,
			Link:   commit.Link,
			Hash:   commit.Hash,
			Repo:   commit.Repo,
			Branch: commit.Branch,
		}
		if !commit.Date.IsZero() {
			apiCommit.Date = &commit.Date
		}
		res = append(res, apiCommit)
	}
	return res
}

func getExtAPIDescrForBugGroups(bugGroups []*uiBugGroup) *api.BugGroup {
	var bugs []api.BugSummary
	for _, group := range bugGroups {
		for _, bug := range group.Bugs {
			bugs = append(bugs, api.BugSummary{
				Title:      bug.Title,
				Link:       bug.Link,
				FixCommits: getBugFixCommits(bug),
			})
		}
	}
	return &api.BugGroup{
		Version: api.Version,
		Bugs:    bugs,
	}
}

type publicKernelTree struct {
	Repo   string `json:"repo"`
	Branch string `json:"branch"`
}

type publicBackportBug struct {
	Namespace       string `json:"namespace"`
	Title           string `json:"title"`
	ConfigLink      string `json:"config_link"`
	SyzReproLink    string `json:"syz_repro_link"`
	CReproLink      string `json:"c_repro_link"`
	SyzkallerCommit string `json:"syzkaller_commit"`
}

type publicMissingBackport struct {
	From   publicKernelTree    `json:"from"`
	To     publicKernelTree    `json:"to"`
	Commit string              `json:"commit"`
	Title  string              `json:"title"`
	Bugs   []publicBackportBug `json:"bugs"`
}

type publicAPIBackports struct {
	Version int                     `json:"version"`
	List    []publicMissingBackport `json:"list"`
}

func getExtAPIDescrForBackports(groups []*uiBackportGroup) *publicAPIBackports {
	return &publicAPIBackports{
		Version: api.Version,
		List: func() []publicMissingBackport {
			var res []publicMissingBackport
			for _, group := range groups {
				from := publicKernelTree{
					Repo:   group.From.URL,
					Branch: group.From.Branch,
				}
				to := publicKernelTree{
					Repo:   group.To.URL,
					Branch: group.To.Branch,
				}
				for _, backport := range group.List {
					record := publicMissingBackport{
						From:   from,
						To:     to,
						Commit: backport.Commit.Hash,
						Title:  backport.Commit.Title,
					}
					for ns, bugs := range backport.Bugs {
						for _, info := range bugs {
							record.Bugs = append(record.Bugs, publicBackportBug{
								Namespace:       ns,
								Title:           info.Bug.Title,
								ConfigLink:      info.Crash.KernelConfigLink,
								CReproLink:      info.Crash.ReproCLink,
								SyzReproLink:    info.Crash.ReproSyzLink,
								SyzkallerCommit: info.Crash.SyzkallerCommit,
							})
						}
					}
					res = append(res, record)
				}
			}
			return res
		}(),
	}
}

func GetJSONDescrFor(page interface{}) ([]byte, error) {
	var res interface{}
	switch i := page.(type) {
	case *uiBugPage:
		res = getExtAPIDescrForBug(i.Bug)
	case *uiTerminalPage:
		res = getExtAPIDescrForBugGroups([]*uiBugGroup{i.Bugs})
	case *uiMainPage:
		res = getExtAPIDescrForBugGroups(i.Groups)
	case *uiBackportsPage:
		res = getExtAPIDescrForBackports(i.Groups)
	default:
		return nil, ErrClientNotFound
	}
	return json.MarshalIndent(res, "", "\t")
}

func writeExtAPICoverageFor(ctx context.Context, w io.Writer, ns, repo string, p *coverageHeatmapParams) error {
	// By default, return the previous month coverage. It guarantees the good numbers.
	//
	// The alternative is to return the current month.
	// The numbers will jump every day, on the 1st date may drop down.
	tps, err := coveragedb.GenNPeriodsTill(1, civil.DateOf(time.Now()).AddDays(-31), "month")
	if err != nil {
		return fmt.Errorf("coveragedb.GenNPeriodsTill: %w", err)
	}

	covDBClient := getCoverageDBClient(ctx)
	ff, err := coveragedb.MakeFuncFinder(ctx, covDBClient, ns, tps[0])
	if err != nil {
		return fmt.Errorf("coveragedb.MakeFuncFinder: %w", err)
	}
	subsystem := ""
	manager := ""
	if p != nil {
		subsystem = p.subsystem
		manager = p.manager
	}
	covCh, errCh := coveragedb.FilesCoverageStream(ctx, covDBClient,
		&coveragedb.SelectScope{
			Ns:        ns,
			Subsystem: subsystem,
			Manager:   manager,
			Periods:   tps,
		})
	if err := writeFileCoverage(ctx, w, repo, ff, covCh); err != nil {
		return fmt.Errorf("populateFileCoverage: %w", err)
	}
	if err := <-errCh; err != nil {
		return fmt.Errorf("coveragedb.FilesCoverageStream: %w", err)
	}
	return nil
}

func writeFileCoverage(ctx context.Context, w io.Writer, repo string, ff *coveragedb.FunctionFinder,
	covCh <-chan *coveragedb.FileCoverageWithLineInfo) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "\t")
	for {
		select {
		case fileCov := <-covCh:
			if fileCov == nil {
				return nil
			}
			funcsCov, err := genFuncsCov(fileCov, ff)
			if err != nil {
				return fmt.Errorf("genFuncsCov: %w", err)
			}
			if err := enc.Encode(&cover.FileCoverage{
				Repo:      repo,
				Commit:    fileCov.Commit,
				FilePath:  fileCov.Filepath,
				Functions: funcsCov,
			}); err != nil {
				return fmt.Errorf("enc.Encode: %w", err)
			}
		case <-ctx.Done():
			return nil
		}
	}
}

func genFuncsCov(fc *coveragedb.FileCoverageWithLineInfo, ff *coveragedb.FunctionFinder,
) ([]*cover.FuncCoverage, error) {
	nameToLines := map[string][]*cover.Block{}
	for i, hitCount := range fc.HitCounts {
		lineNum := int(fc.LinesInstrumented[i])
		funcName, err := ff.FileLineToFuncName(fc.Filepath, lineNum)
		if err != nil {
			return nil, fmt.Errorf("ff.FileLineToFuncName: %w", err)
		}
		nameToLines[funcName] = append(nameToLines[funcName], &cover.Block{
			HitCount: int(hitCount),
			FromLine: lineNum,
			FromCol:  0,
			ToLine:   lineNum,
			ToCol:    -1,
		})
	}

	var res []*cover.FuncCoverage
	for funcName, blocks := range nameToLines {
		res = append(res, &cover.FuncCoverage{
			FuncName: funcName,
			Blocks:   blocks,
		})
	}
	return res, nil
}
