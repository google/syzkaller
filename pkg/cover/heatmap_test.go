// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package cover

import (
	"context"
	"testing"
	"time"

	"cloud.google.com/go/civil"
	"github.com/google/syzkaller/pkg/coveragedb"
	"github.com/google/syzkaller/pkg/coveragedb/mocks"
	"github.com/google/syzkaller/pkg/coveragedb/spannerclient"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"google.golang.org/api/iterator"
)

func TestFilesCoverageWithDetails(t *testing.T) {
	period, _ := coveragedb.MakeTimePeriod(
		civil.Date{Year: 2025, Month: 1, Day: 1},
		"day")
	tests := []struct {
		name       string
		scope      *SelectScope
		client     func() spannerclient.SpannerClient
		onlyUnique bool
		want       []*fileCoverageWithDetails
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
				Periods: []coveragedb.TimePeriod{period},
			},
			client:  func() spannerclient.SpannerClient { return emptyCoverageDBFixture(t, 1) },
			want:    nil,
			wantErr: false,
		},
		{
			name: "single day, unique coverage, empty DB => no coverage",
			scope: &SelectScope{
				Ns:      "upstream",
				Periods: []coveragedb.TimePeriod{period},
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
				Periods: []coveragedb.TimePeriod{period},
			},
			client: func() spannerclient.SpannerClient {
				return fullCoverageDBFixture(
					t,
					[]*fileCoverageWithLineInfo{
						{
							fileCoverageWithDetails: fileCoverageWithDetails{
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
			want: []*fileCoverageWithDetails{
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
				Periods: []coveragedb.TimePeriod{period},
			},
			client: func() spannerclient.SpannerClient {
				return fullCoverageDBFixture(
					t,
					[]*fileCoverageWithLineInfo{
						{
							fileCoverageWithDetails: fileCoverageWithDetails{
								Filepath:     "file1",
								Instrumented: 3,
								Covered:      3,
							},
							LinesInstrumented: []int64{1, 2, 3},
							HitCounts:         []int64{1, 1, 1},
						},
					},
					[]*fileCoverageWithLineInfo{
						{
							fileCoverageWithDetails: fileCoverageWithDetails{
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
			want: []*fileCoverageWithDetails{
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
				Periods: []coveragedb.TimePeriod{period},
			},
			client: func() spannerclient.SpannerClient {
				return fullCoverageDBFixture(
					t,
					[]*fileCoverageWithLineInfo{
						{
							fileCoverageWithDetails: fileCoverageWithDetails{
								Filepath:     "file1",
								Instrumented: 5,
								Covered:      5,
							},
							LinesInstrumented: []int64{1, 2, 3, 4, 5},
							HitCounts:         []int64{3, 4, 5, 6, 7},
						},
					},
					[]*fileCoverageWithLineInfo{
						{
							fileCoverageWithDetails: fileCoverageWithDetails{
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
			want: []*fileCoverageWithDetails{
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
			got, gotErr := filesCoverageWithDetails(
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
	t *testing.T, full, partial []*fileCoverageWithLineInfo,
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

func newRowIteratorMock(t *testing.T, events []*fileCoverageWithLineInfo,
) *mocks.RowIterator {
	m := mocks.NewRowIterator(t)
	m.On("Stop").Once().Return()
	for _, item := range events {
		mRow := mocks.NewRow(t)
		mRow.On("ToStruct", mock.Anything).
			Run(func(args mock.Arguments) {
				arg := args.Get(0).(*fileCoverageWithLineInfo)
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

func TestFilesCoverageToTemplateData(t *testing.T) {
	tests := []struct {
		name  string
		input []*fileCoverageWithDetails
		want  *templateHeatmap
	}{
		{
			name:  "empty input",
			input: []*fileCoverageWithDetails{},
			want: &templateHeatmap{
				Root: &templateHeatmapRow{
					Items: []*templateHeatmapRow{},
					IsDir: true,
				},
			},
		},
		{
			name: "single file",
			input: []*fileCoverageWithDetails{
				{
					Filepath:     "file1",
					Instrumented: 1,
					Covered:      1,
					TimePeriod:   makeTimePeriod(t, civil.Date{Year: 2024, Month: time.July, Day: 1}, coveragedb.DayPeriod),
					Commit:       "commit1",
				},
			},
			want: &templateHeatmap{
				Root: &templateHeatmapRow{
					Items: []*templateHeatmapRow{
						{
							Items:               []*templateHeatmapRow{},
							Name:                "file1",
							Coverage:            []int64{100},
							IsDir:               false,
							Depth:               0,
							LastDayInstrumented: 1,
							Tooltips: []string{
								"Instrumented:\t1 blocks\nCovered:\t1 blocks",
							},
							FileCoverageLink: []string{
								"/graph/coverage/file?dateto=2024-07-01&period=day&commit=commit1&filepath=file1"},
						},
					},
					Name:                "",
					Coverage:            []int64{100},
					IsDir:               true,
					Depth:               0,
					LastDayInstrumented: 1,
					Tooltips: []string{
						"Instrumented:\t1 blocks\nCovered:\t1 blocks",
					},
				},
				Periods: []string{"2024-07-01(1)"},
			},
		},
		{
			name: "tree data",
			input: []*fileCoverageWithDetails{
				{
					Filepath:     "dir/file2",
					Instrumented: 1,
					Covered:      0,
					TimePeriod:   makeTimePeriod(t, civil.Date{Year: 2024, Month: time.July, Day: 2}, coveragedb.DayPeriod),
					Commit:       "commit2",
				},
				{
					Filepath:     "dir/file1",
					Instrumented: 1,
					Covered:      1,
					TimePeriod:   makeTimePeriod(t, civil.Date{Year: 2024, Month: time.July, Day: 1}, coveragedb.DayPeriod),
					Commit:       "commit1",
				},
			},
			want: &templateHeatmap{
				Root: &templateHeatmapRow{
					Items: []*templateHeatmapRow{
						{
							Items: []*templateHeatmapRow{
								{
									Items:               []*templateHeatmapRow{},
									Name:                "file1",
									Coverage:            []int64{100, 0},
									IsDir:               false,
									Depth:               1,
									LastDayInstrumented: 0,
									Tooltips: []string{
										"Instrumented:\t1 blocks\nCovered:\t1 blocks",
										"Instrumented:\t0 blocks\nCovered:\t0 blocks",
									},
									FileCoverageLink: []string{
										"/graph/coverage/file?dateto=2024-07-01&period=day&commit=commit1&filepath=dir/file1",
										"/graph/coverage/file?dateto=2024-07-02&period=day&commit=commit2&filepath=dir/file1"},
								},
								{
									Items:               []*templateHeatmapRow{},
									Name:                "file2",
									Coverage:            []int64{0, 0},
									IsDir:               false,
									Depth:               1,
									LastDayInstrumented: 1,
									Tooltips: []string{
										"Instrumented:\t0 blocks\nCovered:\t0 blocks",
										"Instrumented:\t1 blocks\nCovered:\t0 blocks",
									},
									FileCoverageLink: []string{
										"/graph/coverage/file?dateto=2024-07-01&period=day&commit=commit1&filepath=dir/file2",
										"/graph/coverage/file?dateto=2024-07-02&period=day&commit=commit2&filepath=dir/file2"},
								},
							},
							Name:                "dir",
							Coverage:            []int64{100, 0},
							IsDir:               true,
							Depth:               0,
							LastDayInstrumented: 1,
							Tooltips: []string{
								"Instrumented:\t1 blocks\nCovered:\t1 blocks",
								"Instrumented:\t1 blocks\nCovered:\t0 blocks",
							},
						},
					},
					Name:                "",
					Coverage:            []int64{100, 0},
					LastDayInstrumented: 1,
					Tooltips: []string{
						"Instrumented:\t1 blocks\nCovered:\t1 blocks",
						"Instrumented:\t1 blocks\nCovered:\t0 blocks",
					},
					IsDir: true,
				},
				Periods: []string{"2024-07-01(1)", "2024-07-02(1)"},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := filesCoverageToTemplateData(test.input)
			assert.EqualExportedValues(t, test.want, got)
		})
	}
}

func makeTimePeriod(t *testing.T, targetDate civil.Date, periodType string) coveragedb.TimePeriod {
	tp, err := coveragedb.MakeTimePeriod(targetDate, periodType)
	assert.NoError(t, err)
	return tp
}
