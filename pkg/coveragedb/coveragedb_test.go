// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package coveragedb

import (
	"context"
	"testing"

	"cloud.google.com/go/civil"
	"github.com/google/syzkaller/pkg/coveragedb/mocks"
	"github.com/google/syzkaller/pkg/coveragedb/spannerclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"google.golang.org/api/iterator"
)

func TestFilesCoverageWithDetails(t *testing.T) {
	period, _ := MakeTimePeriod(
		civil.Date{Year: 2025, Month: 1, Day: 1},
		"day")
	tests := []struct {
		name       string
		scope      *SelectScope
		client     func() spannerclient.SpannerClient
		onlyUnique bool
		want       []*FileCoverageWithDetails
		wantErr    bool
	}{
		{
			name:    "empty scope",
			scope:   &SelectScope{},
			want:    nil,
			wantErr: false,
		},
		{
			name: "single day, no filters, empty DB => no coverage",
			scope: &SelectScope{
				Ns:      "upstream",
				Periods: []TimePeriod{period},
			},
			client:  func() spannerclient.SpannerClient { return emptyCoverageDBFixture(t, 1) },
			want:    nil,
			wantErr: false,
		},
		{
			name: "single day, unique coverage, empty DB => no coverage",
			scope: &SelectScope{
				Ns:      "upstream",
				Periods: []TimePeriod{period},
			},
			client:     func() spannerclient.SpannerClient { return emptyCoverageDBFixture(t, 2) },
			onlyUnique: true,
			want:       nil,
			wantErr:    false,
		},
		{
			name: "single day, unique coverage, empty partial result => 0/3 covered",
			scope: &SelectScope{
				Ns:      "upstream",
				Periods: []TimePeriod{period},
			},
			client: func() spannerclient.SpannerClient {
				return fullCoverageDBFixture(
					t,
					[]*FileCoverageWithLineInfo{
						{
							FileCoverageWithDetails: FileCoverageWithDetails{
								Filepath:     "file1",
								Instrumented: 3,
								Covered:      3,
							},
							LinesInstrumented: []int64{1, 2, 3},
							HitCounts:         []int64{1, 1, 1},
						},
					},
					nil)
			},
			onlyUnique: true,
			want: []*FileCoverageWithDetails{
				{
					Filepath:     "file1",
					Instrumented: 3,
					Covered:      0,
					TimePeriod:   period,
				},
			},
			wantErr: false,
		},
		{
			name: "single day, unique coverage, full result match => 3/3 covered",
			scope: &SelectScope{
				Ns:      "upstream",
				Periods: []TimePeriod{period},
			},
			client: func() spannerclient.SpannerClient {
				return fullCoverageDBFixture(
					t,
					[]*FileCoverageWithLineInfo{
						{
							FileCoverageWithDetails: FileCoverageWithDetails{
								Filepath:     "file1",
								Instrumented: 3,
								Covered:      3,
							},
							LinesInstrumented: []int64{1, 2, 3},
							HitCounts:         []int64{1, 1, 1},
						},
					},
					[]*FileCoverageWithLineInfo{
						{
							FileCoverageWithDetails: FileCoverageWithDetails{
								Filepath:     "file1",
								Instrumented: 3,
								Covered:      3,
							},
							LinesInstrumented: []int64{1, 2, 3},
							HitCounts:         []int64{1, 1, 1},
						},
					})
			},
			onlyUnique: true,
			want: []*FileCoverageWithDetails{
				{
					Filepath:     "file1",
					Instrumented: 3,
					Covered:      3,
					TimePeriod:   period,
				},
			},
			wantErr: false,
		},
		{
			name: "single day, unique coverage, partial result match => 3/5 covered",
			scope: &SelectScope{
				Ns:      "upstream",
				Periods: []TimePeriod{period},
			},
			client: func() spannerclient.SpannerClient {
				return fullCoverageDBFixture(
					t,
					[]*FileCoverageWithLineInfo{
						{
							FileCoverageWithDetails: FileCoverageWithDetails{
								Filepath:     "file1",
								Instrumented: 5,
								Covered:      5,
							},
							LinesInstrumented: []int64{1, 2, 3, 4, 5},
							HitCounts:         []int64{3, 4, 5, 6, 7},
						},
					},
					[]*FileCoverageWithLineInfo{
						{
							FileCoverageWithDetails: FileCoverageWithDetails{
								Filepath:     "file1",
								Instrumented: 4,
								Covered:      3,
							},
							LinesInstrumented: []int64{1, 2, 3, 5},
							HitCounts:         []int64{3, 0, 5, 7},
						},
					})
			},
			onlyUnique: true,
			want: []*FileCoverageWithDetails{
				{
					Filepath:     "file1",
					Instrumented: 5,
					Covered:      3,
					TimePeriod:   period,
				},
			},
			wantErr: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testClient spannerclient.SpannerClient
			if test.client != nil {
				testClient = test.client()
			}
			got, gotErr := FilesCoverageWithDetails(
				context.Background(),
				testClient, test.scope, test.onlyUnique)
			if test.wantErr {
				assert.Error(t, gotErr)
			} else {
				assert.NoError(t, gotErr)
			}
			assert.Equal(t, test.want, got)
		})
	}
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

func fullCoverageDBFixture(
	t *testing.T, full, partial []*FileCoverageWithLineInfo,
) spannerclient.SpannerClient {
	mPartialTran := mocks.NewReadOnlyTransaction(t)
	mPartialTran.On("Query", mock.Anything, mock.Anything).
		Return(newRowIteratorMock(t, partial)).Once()

	mFullTran := mocks.NewReadOnlyTransaction(t)
	mFullTran.On("Query", mock.Anything, mock.Anything).
		Return(newRowIteratorMock(t, full)).Once()

	m := mocks.NewSpannerClient(t)
	m.On("Single").
		Return(mPartialTran).Once()
	m.On("Single").
		Return(mFullTran).Once()
	return m
}

func newRowIteratorMock(t *testing.T, events []*FileCoverageWithLineInfo,
) *mocks.RowIterator {
	m := mocks.NewRowIterator(t)
	m.On("Stop").Once().Return()
	for _, item := range events {
		mRow := mocks.NewRow(t)
		mRow.On("ToStruct", mock.Anything).
			Run(func(args mock.Arguments) {
				arg := args.Get(0).(*FileCoverageWithLineInfo)
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
