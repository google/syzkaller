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
					TimePeriod:   coveragedb.TimePeriod{DateTo: civil.Date{Year: 2024, Month: time.July, Day: 1}, Days: 1},
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
								"/upstream/graph/coverage/file?dateto=2024-07-01&period=day&commit=commit&filepath=file1"},
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
					TimePeriod:   coveragedb.TimePeriod{DateTo: civil.Date{Year: 2024, Month: time.July, Day: 2}, Days: 1},
				},
				{
					Filepath:     "dir/file1",
					Instrumented: 1,
					Covered:      1,
					TimePeriod:   coveragedb.TimePeriod{DateTo: civil.Date{Year: 2024, Month: time.July, Day: 1}, Days: 1},
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
										"/upstream/graph/coverage/file?dateto=2024-07-01&period=day&commit=commit&filepath=dir/file1",
										"/upstream/graph/coverage/file?dateto=2024-07-02&period=day&commit=commit&filepath=dir/file1"},
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
										"/upstream/graph/coverage/file?dateto=2024-07-01&period=day&commit=commit&filepath=dir/file2",
										"/upstream/graph/coverage/file?dateto=2024-07-02&period=day&commit=commit&filepath=dir/file2"},
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
