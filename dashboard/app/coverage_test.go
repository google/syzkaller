// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"strings"
	"testing"

	"github.com/google/syzkaller/pkg/coveragedb"
	"github.com/google/syzkaller/pkg/coveragedb/mocks"
	"github.com/google/syzkaller/pkg/coveragedb/spannerclient"
	"github.com/google/syzkaller/pkg/covermerger"
	mergermocks "github.com/google/syzkaller/pkg/covermerger/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"google.golang.org/api/iterator"
)

func TestFileCoverage(t *testing.T) {
	tests := []struct {
		name      string
		covDB     func(t *testing.T) spannerclient.SpannerClient
		fileProv  func(t *testing.T) covermerger.FileVersProvider
		url       string
		wantInRes []string
	}{
		{
			name:     "empty db",
			covDB:    func(t *testing.T) spannerclient.SpannerClient { return emptyCoverageDBFixture(t, 1) },
			fileProv: func(t *testing.T) covermerger.FileVersProvider { return staticFileProvider(t) },
			url: "/test2/coverage/file?dateto=2025-01-31&period=month" +
				"&commit=c0e75905caf368e19aab585d20151500e750de89&filepath=virt/kvm/kvm_main.c",
			wantInRes: []string{"1 line1"},
		},
		{
			name:     "regular db",
			covDB:    func(t *testing.T) spannerclient.SpannerClient { return coverageDBFixture(t) },
			fileProv: func(t *testing.T) covermerger.FileVersProvider { return staticFileProvider(t) },
			url: "/test2/coverage/file?dateto=2025-01-31&period=month" +
				"&commit=c0e75905caf368e19aab585d20151500e750de89&filepath=virt/kvm/kvm_main.c",
			wantInRes: []string{
				"4      1 line1",
				"5      2 line2",
				"6      3 line3"},
		},
		{
			name:     "multimanager db",
			covDB:    func(t *testing.T) spannerclient.SpannerClient { return multiManagerCovDBFixture(t) },
			fileProv: func(t *testing.T) covermerger.FileVersProvider { return staticFileProvider(t) },
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

func emptyCoverageDBFixture(t *testing.T, times int) spannerclient.SpannerClient {
	mRowIterator := mocks.NewRowIterator(t)
	mRowIterator.On("Stop").Return().Times(times)
	mRowIterator.On("Next").
		Return(nil, iterator.Done).Times(times)

	mTran := mocks.NewReadOnlyTransaction(t)
	mTran.On("Query", mock.Anything, mock.Anything).
		Return(mRowIterator).Times(times)

	m := mocks.NewSpannerClient(t)
	m.On("Single").
		Return(mTran).Times(times)
	return m
}

func coverageDBFixture(t *testing.T) spannerclient.SpannerClient {
	mRowIt := newRowIteratorMock(t, []*coveragedb.LinesCoverage{{
		LinesInstrumented: []int64{1, 2, 3},
		HitCounts:         []int64{4, 5, 6},
	}})

	mTran := mocks.NewReadOnlyTransaction(t)
	mTran.On("Query", mock.Anything, mock.Anything).
		Return(mRowIt).Once()

	m := mocks.NewSpannerClient(t)
	m.On("Single").
		Return(mTran).Once()
	return m
}

func multiManagerCovDBFixture(t *testing.T) spannerclient.SpannerClient {
	mReadFullCoverageTran := mocks.NewReadOnlyTransaction(t)
	mReadFullCoverageTran.On("Query", mock.Anything, mock.Anything).
		Return(newRowIteratorMock(t, []*coveragedb.LinesCoverage{{
			LinesInstrumented: []int64{1, 2, 3},
			HitCounts:         []int64{4, 5, 6},
		}})).Once()

	mReadPartialCoverageTran := mocks.NewReadOnlyTransaction(t)
	mReadPartialCoverageTran.On("Query", mock.Anything, mock.Anything).
		Return(newRowIteratorMock(t, []*coveragedb.LinesCoverage{{
			LinesInstrumented: []int64{1, 2},
			HitCounts:         []int64{3, 5},
		}})).Once()

	m := mocks.NewSpannerClient(t)
	// The order matters. Full coverage is fetched second.
	m.On("Single").
		Return(mReadPartialCoverageTran).Once()
	m.On("Single").
		Return(mReadFullCoverageTran).Once()

	return m
}

func newRowIteratorMock[K any](t *testing.T, cov []*K,
) *mocks.RowIterator {
	m := mocks.NewRowIterator(t)
	m.On("Stop").Once().Return()
	for _, item := range cov {
		mRow := mocks.NewRow(t)
		mRow.On("ToStruct", mock.Anything).
			Run(func(args mock.Arguments) {
				arg := args.Get(0).(*K)
				*arg = *item
			}).
			Return(nil).Once()

		m.On("Next").
			Return(mRow, nil).Once()
	}

	m.On("Next").
		Return(nil, iterator.Done).Once()
	return m
}
