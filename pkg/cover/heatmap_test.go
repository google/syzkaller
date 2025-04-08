// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package cover

import (
	"testing"
	"time"

	"cloud.google.com/go/civil"
	"github.com/google/syzkaller/pkg/coveragedb"
	"github.com/stretchr/testify/assert"
)

func TestFilesCoverageToTemplateData(t *testing.T) {
	tests := []struct {
		name  string
		input []*coveragedb.FileCoverageWithDetails
		want  *templateHeatmap
	}{
		{
			name:  "empty input",
			input: []*coveragedb.FileCoverageWithDetails{},
			want: &templateHeatmap{
				Root: &templateHeatmapRow{
					IsDir: true,
				},
			},
		},
		{
			name: "single file",
			input: []*coveragedb.FileCoverageWithDetails{
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
							Name:     "file1",
							Coverage: []int64{100},
							Covered:  []int64{1},
							IsDir:    false,
							Depth:    0,
							Summary:  1,
							Tooltips: []string{
								"Instrumented:\t1 blocks\nCovered:\t1 blocks",
							},
							FileCoverageLink: []string{
								"/coverage/file?dateto=2024-07-01&period=day&commit=commit1&filepath=file1"},
						},
					},
					Name:     "",
					Coverage: []int64{100},
					Covered:  []int64{1},
					IsDir:    true,
					Depth:    0,
					Summary:  1,
					Tooltips: []string{
						"Instrumented:\t1 blocks\nCovered:\t1 blocks",
					},
				},
				Periods: []string{"2024-07-01(1)"},
			},
		},
		{
			name: "tree data",
			input: []*coveragedb.FileCoverageWithDetails{
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
									Name:     "file1",
									Coverage: []int64{100, 0},
									Covered:  []int64{1, 0},
									IsDir:    false,
									Depth:    1,
									Summary:  0,
									Tooltips: []string{
										"Instrumented:\t1 blocks\nCovered:\t1 blocks",
										"Instrumented:\t0 blocks\nCovered:\t0 blocks",
									},
									FileCoverageLink: []string{
										"/coverage/file?dateto=2024-07-01&period=day&commit=commit1&filepath=dir/file1",
										"/coverage/file?dateto=2024-07-02&period=day&commit=commit2&filepath=dir/file1"},
								},
								{
									Name:     "file2",
									Coverage: []int64{0, 0},
									Covered:  []int64{0, 0},
									IsDir:    false,
									Depth:    1,
									Summary:  1,
									Tooltips: []string{
										"Instrumented:\t0 blocks\nCovered:\t0 blocks",
										"Instrumented:\t1 blocks\nCovered:\t0 blocks",
									},
									FileCoverageLink: []string{
										"/coverage/file?dateto=2024-07-01&period=day&commit=commit1&filepath=dir/file2",
										"/coverage/file?dateto=2024-07-02&period=day&commit=commit2&filepath=dir/file2"},
								},
							},
							Name:     "dir",
							Coverage: []int64{100, 0},
							Covered:  []int64{1, 0},
							IsDir:    true,
							Depth:    0,
							Summary:  1,
							Tooltips: []string{
								"Instrumented:\t1 blocks\nCovered:\t1 blocks",
								"Instrumented:\t1 blocks\nCovered:\t0 blocks",
							},
						},
					},
					Name:     "",
					Coverage: []int64{100, 0},
					Covered:  []int64{1, 0},
					Summary:  1,
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

// nolint: dupl
func TestFormatResult(t *testing.T) {
	tests := []struct {
		name   string
		sample *templateHeatmap
		input  Format
		want   *templateHeatmap
	}{
		{
			name: "remove empty",
			input: Format{
				DropCoveredLines0: true,
			},
			sample: &templateHeatmap{
				Root: &templateHeatmapRow{
					Items: []*templateHeatmapRow{
						{
							Items: []*templateHeatmapRow{
								{
									Name:    "file1",
									Covered: []int64{0, 0},
									Depth:   1,
								},
							},
							Name:    "dir",
							Covered: []int64{1, 0},
							IsDir:   true,
						},
					},
					Covered: []int64{1, 0},
					IsDir:   true,
				},
			},
			want: &templateHeatmap{
				Root: &templateHeatmapRow{
					Items: []*templateHeatmapRow{
						{
							Name:    "dir",
							Covered: []int64{1, 0},
							IsDir:   true,
						},
					},
					Covered: []int64{1, 0},
					IsDir:   true,
				},
			},
		},
		{
			name: "remove small lines drop",
			input: Format{
				FilterMinCoveredLinesDrop: 10,
			},
			sample: &templateHeatmap{
				Root: &templateHeatmapRow{
					Items: []*templateHeatmapRow{
						{
							Items: []*templateHeatmapRow{
								{
									Name:    "file1",
									Covered: []int64{5, 0},
									Depth:   1,
								},
								{
									Name:    "file2",
									Covered: []int64{10, 0},
									Depth:   1,
								},
							},
							Name:    "dir",
							Covered: []int64{1, 1},
							IsDir:   true,
						},
					},
					Covered: []int64{1, 1},
					IsDir:   true,
				},
			},
			want: &templateHeatmap{
				Root: &templateHeatmapRow{
					Items: []*templateHeatmapRow{
						{
							Items: []*templateHeatmapRow{
								{
									Name:    "file2",
									Covered: []int64{10, 0},
									Depth:   1,
								},
							},
							Name:    "dir",
							Covered: []int64{1, 1},
							IsDir:   true,
						},
					},
					Covered: []int64{1, 1},
					IsDir:   true,
				},
			},
		},
		{
			name: "order by the lines drop",
			input: Format{
				OrderByCoveredLinesDrop: true,
			},
			sample: &templateHeatmap{
				Root: &templateHeatmapRow{
					Items: []*templateHeatmapRow{
						{
							Items: []*templateHeatmapRow{
								{
									Name:    "file1",
									Covered: []int64{5, 0},
									Depth:   1,
								},
								{
									Name:    "file2",
									Covered: []int64{10, 0},
									Depth:   1,
								},
							},
							Name:    "dir",
							Covered: []int64{1, 1},
							IsDir:   true,
						},
					},
					Covered: []int64{1, 1},
					IsDir:   true,
				},
			},
			want: &templateHeatmap{
				Root: &templateHeatmapRow{
					Items: []*templateHeatmapRow{
						{
							Items: []*templateHeatmapRow{
								{
									Name:    "file2",
									Covered: []int64{10, 0},
									Depth:   1,
									Summary: -10,
								},
								{
									Name:    "file1",
									Covered: []int64{5, 0},
									Depth:   1,
									Summary: -5,
								},
							},
							Name:    "dir",
							Covered: []int64{1, 1},
							IsDir:   true,
						},
					},
					Covered: []int64{1, 1},
					IsDir:   true,
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			FormatResult(test.sample, test.input)
			assert.Equal(t, test.want, test.sample)
		})
	}
}

func makeTimePeriod(t *testing.T, targetDate civil.Date, periodType string) coveragedb.TimePeriod {
	tp, err := coveragedb.MakeTimePeriod(targetDate, periodType)
	assert.NoError(t, err)
	return tp
}
