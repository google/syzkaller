// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package coveragedb

import (
	"context"
	"encoding/json"
	"io"
	"strings"
	"testing"
	"time"

	"cloud.google.com/go/spanner"
	"github.com/google/syzkaller/pkg/coveragedb/mocks"
	"github.com/google/syzkaller/pkg/subsystem"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

//go:generate ../../tools/mockery.sh --name SpannerClient -r
//go:generate ../../tools/mockery.sh --name ReadOnlyTransaction -r
//go:generate ../../tools/mockery.sh --name RowIterator -r
//go:generate ../../tools/mockery.sh --name Row -r

type spannerMockTune func(*testing.T, *mocks.SpannerClient)

func TestSaveMergeResult(t *testing.T) {
	tests := []struct {
		name     string
		sss      []*subsystem.Subsystem
		jsonl    io.Reader
		descr    *HistoryRecord
		mockTune spannerMockTune
		wantErr  bool
		wantRows int
	}{
		{
			name:    "empty jsonl",
			jsonl:   strings.NewReader(`{}`),
			wantErr: true,
		},
		{
			name:    "wrong jsonl content",
			jsonl:   strings.NewReader(`{a}`),
			wantErr: true,
		},
		// nolint: dupl
		{
			name:     "1 MCR record, Ok",
			jsonl:    strings.NewReader(`{"MCR":{"FileData":{}}}`),
			descr:    &HistoryRecord{},
			wantRows: 3, // 1 in files, 1 in file_subsystems and 1 in merge_history
			mockTune: func(t *testing.T, m *mocks.SpannerClient) {
				m.
					On("Apply", mock.Anything, mock.Anything).
					Return(time.Now(), nil).
					Once()
			},
		},
		// nolint: dupl
		{
			name:     "1 FC record, Ok",
			jsonl:    strings.NewReader(`{"FL":{}}`),
			descr:    &HistoryRecord{},
			wantRows: 2, // 1 in functions and 1 in merge_history
			mockTune: func(t *testing.T, m *mocks.SpannerClient) {
				m.
					On("Apply", mock.Anything, mock.Anything).
					Return(time.Now(), nil).
					Once()
			},
		},
		{
			name: "2 records, Ok",
			jsonl: strings.NewReader(`	{"MCR":{"FileData":{}}}
																		{"MCR":{"FileData":{}}}`),
			descr:    &HistoryRecord{},
			wantRows: 5,
			mockTune: func(t *testing.T, m *mocks.SpannerClient) {
				m.
					On("Apply",
						mock.Anything,
						mock.MatchedBy(func(ms []*spanner.Mutation) bool {
							// 2 in files, 2 in file_subsystems and 1 in merge_history
							return len(ms) == 5
						})).
					Return(time.Now(), nil).
					Once()
			},
		},
		{
			name:     "2k records, Ok",
			jsonl:    strings.NewReader(strings.Repeat("{\"MCR\":{\"FileData\":{}}}\n", 2000)),
			descr:    &HistoryRecord{},
			wantRows: 4001,
			mockTune: func(t *testing.T, m *mocks.SpannerClient) {
				m.
					On("Apply",
						mock.Anything,
						mock.MatchedBy(func(ms []*spanner.Mutation) bool {
							// 2k in files, 2k in file_subsystems
							return len(ms) == 1000
						})).
					Return(time.Now(), nil).
					Times(4).
					On("Apply",
						mock.Anything,
						mock.MatchedBy(func(ms []*spanner.Mutation) bool {
							// And 1 in merge_history.
							return len(ms) == 1
						})).
					Return(time.Now(), nil).
					Once()
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			spannerMock := mocks.NewSpannerClient(t)
			if test.mockTune != nil {
				test.mockTune(t, spannerMock)
			}
			gotRows, err := SaveMergeResult(
				context.Background(),
				spannerMock,
				test.descr,
				json.NewDecoder(test.jsonl), test.sss)
			if test.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, test.wantRows, gotRows)
		})
	}
}
