// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package cover

import (
	"testing"
	"time"

	"cloud.google.com/go/civil"
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
					Dateto:       civil.Date{Year: 2024, Month: time.July, Day: 1},
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
						},
					},
					Name:                "",
					Coverage:            []int64{100},
					IsDir:               false,
					Depth:               0,
					LastDayInstrumented: 1,
					Tooltips: []string{
						"Instrumented:\t1 blocks\nCovered:\t1 blocks",
					},
				},
				Dates: []string{"2024-07-01"},
			},
		},
		{
			name: "tree data",
			input: []*fileCoverageWithDetails{
				{
					Filepath:     "dir/file2",
					Instrumented: 1,
					Covered:      0,
					Dateto:       civil.Date{Year: 2024, Month: time.July, Day: 2},
				},
				{
					Filepath:     "dir/file1",
					Instrumented: 1,
					Covered:      1,
					Dateto:       civil.Date{Year: 2024, Month: time.July, Day: 1},
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
				},
				Dates: []string{"2024-07-01", "2024-07-02"},
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
