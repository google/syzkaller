// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	"cloud.google.com/go/civil"
	"cloud.google.com/go/spanner"
	"github.com/google/syzkaller/pkg/coveragedb"
	"github.com/google/syzkaller/pkg/coveragedb/testutil"
	"github.com/google/syzkaller/pkg/covermerger"
	mergermocks "github.com/google/syzkaller/pkg/covermerger/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func setCoverageDBClient(ctx context.Context, client *spanner.Client) context.Context {
	return context.WithValue(ctx, &keyCoverageDBClient, client)
}

func TestFileCoverage_BadRequest(t *testing.T) {
	badURL := "/test2/coverage/file?dateto=2025-01-31'&period=month" +
		"&commit=c0e75905caf368e19aab585d20151500e750de89&filepath=virt/kvm/kvm_main.c"
	c := NewCtx(t)
	defer c.Close()
	c.setCoverageMocks("test2", nil, nil)
	_, err := c.GET(badURL)
	var httpErr *HTTPError
	assert.True(t, errors.As(err, &httpErr))
	assert.Equal(t, http.StatusBadRequest, httpErr.Code)
}

func TestFileCoverage(t *testing.T) {
	tests := []struct {
		name      string
		covDB     func(t *testing.T) *spanner.Client
		fileProv  func(t *testing.T) covermerger.FileVersProvider
		url       string
		wantInRes []string
	}{
		{
			name:     "empty db",
			covDB:    emptyCoverageDBFixture,
			fileProv: staticFileProvider,
			url: "/test2/coverage/file?dateto=2025-01-31&period=month" +
				"&commit=c0e75905caf368e19aab585d20151500e750de89&filepath=virt/kvm/kvm_main.c",
			wantInRes: []string{"1 line1"},
		},
		{
			name:     "regular db",
			covDB:    coverageDBFixture,
			fileProv: staticFileProvider,
			url: "/test2/coverage/file?dateto=2025-01-31&period=month" +
				"&commit=c0e75905caf368e19aab585d20151500e750de89&filepath=virt/kvm/kvm_main.c",
			wantInRes: []string{
				"4      1 line1",
				"5      2 line2",
				"6      3 line3"},
		},
		{
			name:     "multimanager db",
			covDB:    multiManagerCovDBFixture,
			fileProv: staticFileProvider,
			url: "/test2/coverage/file?dateto=2025-01-31&period=month" +
				"&commit=c0e75905caf368e19aab585d20151500e750de89&filepath=virt/kvm/kvm_main.c" +
				"&manager=special-cc-manager&unique-only=1",
			wantInRes: []string{
				" 0      1 line1", // Covered, is not unique.
				" 5      2 line2", // Covered and is unique.
				"        3 line3", // Covered only by "*" managers.
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c := NewCtx(t)
			defer c.Close()
			c.setCoverageMocks("test2", test.covDB(t), test.fileProv(t))
			fileCovPage, err := c.GET(test.url)
			assert.NoError(t, err)
			got := string(fileCovPage)
			for _, want := range test.wantInRes {
				if !strings.Contains(got, want) {
					t.Errorf(`"%s" wasn't found in "%s"'`, want, got)
				}
			}
		})
	}
}

func staticFileProvider(t *testing.T) covermerger.FileVersProvider {
	m := mergermocks.NewFileVersProvider(t)
	m.On("GetFileVersions", mock.Anything, mock.Anything).
		Return(func(targetFilePath string, repoCommits ...covermerger.RepoCommit,
		) covermerger.FileVersions {
			res := covermerger.FileVersions{}
			for _, rc := range repoCommits {
				res[rc] = `line1
line2
line3`
			}
			return res
		}, nil)
	return m
}

func emptyCoverageDBFixture(t *testing.T) *spanner.Client {
	return testutil.SetupCoverageTestDB(t)
}

func coverageDBFixture(t *testing.T) *spanner.Client {
	client := testutil.SetupCoverageTestDB(t)
	period, _ := coveragedb.MakeTimePeriod(civil.Date{Year: 2025, Month: 1, Day: 31}, "month")
	history := &coveragedb.HistoryRecord{
		Namespace: "test2",
		Repo:      "repo1",
		Commit:    "c0e75905caf368e19aab585d20151500e750de89",
		Duration:  int64(period.Days),
		DateTo:    period.DateTo,
		Session:   "session1",
		Time:      time.Now(),
		TotalRows: 100,
	}
	testutil.InsertCoverageData(t, client, "*", history, []*coveragedb.FileCoverageWithLineInfo{{
		FileCoverageWithDetails: coveragedb.FileCoverageWithDetails{
			Filepath:     "virt/kvm/kvm_main.c",
			Instrumented: 3,
			Covered:      3,
			Subsystems:   []string{"sub1"},
		},
		LinesInstrumented: []int64{1, 2, 3},
		HitCounts:         []int64{4, 5, 6},
	}})
	return client
}

func multiManagerCovDBFixture(t *testing.T) *spanner.Client {
	client := testutil.SetupCoverageTestDB(t)
	period, _ := coveragedb.MakeTimePeriod(civil.Date{Year: 2025, Month: 1, Day: 31}, "month")

	// Full coverage.
	historyFull := &coveragedb.HistoryRecord{
		Namespace: "test2",
		Repo:      "repo-full",
		Commit:    "c0e75905caf368e19aab585d20151500e750de89",
		Duration:  int64(period.Days),
		DateTo:    period.DateTo,
		Session:   "session-full",
		Time:      time.Now(),
		TotalRows: 100,
	}
	testutil.InsertCoverageData(t, client, "*", historyFull, []*coveragedb.FileCoverageWithLineInfo{{
		FileCoverageWithDetails: coveragedb.FileCoverageWithDetails{
			Filepath:     "virt/kvm/kvm_main.c",
			Instrumented: 3,
			Covered:      3,
			Subsystems:   []string{"sub1"},
		},
		LinesInstrumented: []int64{1, 2, 3},
		HitCounts:         []int64{4, 5, 6},
	}})

	// Partial coverage.
	historyPart := &coveragedb.HistoryRecord{
		Namespace: "test2",
		Repo:      "repo-part",
		Commit:    "c0e75905caf368e19aab585d20151500e750de89",
		Duration:  int64(period.Days),
		DateTo:    period.DateTo,
		Session:   "session-part",
		Time:      time.Now(),
		TotalRows: 100,
	}
	testutil.InsertCoverageData(t, client, "special-cc-manager", historyPart, []*coveragedb.FileCoverageWithLineInfo{{
		FileCoverageWithDetails: coveragedb.FileCoverageWithDetails{
			Filepath:     "virt/kvm/kvm_main.c",
			Instrumented: 2,
			Covered:      2,
			Subsystems:   []string{"sub1"},
		},
		LinesInstrumented: []int64{1, 2},
		HitCounts:         []int64{3, 5},
	}})

	return client
}
