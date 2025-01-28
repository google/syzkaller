// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package covermerger

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"cloud.google.com/go/civil"
	"cloud.google.com/go/spanner"
	"github.com/google/syzkaller/pkg/coveragedb"
	"github.com/google/syzkaller/pkg/coveragedb/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
	"golang.org/x/sync/errgroup"
)

var testsPath = "testdata/integration"
var defaultTestWorkdir = testsPath + "/all/test-workdir-covermerger"

func TestMergeCSVWriteJSONL_and_coveragedb_SaveMergeResult(t *testing.T) {
	rc, wc := io.Pipe()
	eg := errgroup.Group{}
	eg.Go(func() error {
		defer wc.Close()
		totalInstrumented, totalCovered, err := MergeCSVWriteJSONL(
			testConfig(
				"git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git",
				"fe46a7dd189e25604716c03576d05ac8a5209743",
				testsPath+"/aesni-intel_glue/test-workdir-covermerger"),
			&coveragedb.HistoryRecord{
				DateTo: civil.DateOf(time.Now()),
			},
			strings.NewReader(readFileOrFail(t, testsPath+"/aesni-intel_glue/bqTable.txt")),
			wc)
		assert.Equal(t, 48, totalInstrumented)
		assert.Equal(t, 45, totalCovered)
		return err
	})
	eg.Go(func() error {
		defer rc.Close()
		gzrc, err := gzip.NewReader(rc)
		assert.NoError(t, err)
		defer gzrc.Close()

		spannerMock := mocks.NewSpannerClient(t)
		spannerMock.
			On("Apply", mock.Anything, mock.MatchedBy(func(ms []*spanner.Mutation) bool {
				// 1 file * (5 managers + 1 manager total) x 2 (to update files and subsystems) + 1 merge_history + 18 functions
				return len(ms) == 13+18
			})).
			Return(time.Now(), nil).
			Once()

		decoder := json.NewDecoder(gzrc)
		decoder.DisallowUnknownFields()

		descr := new(coveragedb.HistoryRecord)
		assert.NoError(t, decoder.Decode(descr))

		_, err = coveragedb.SaveMergeResult(context.Background(), spannerMock, descr, decoder, nil)
		return err
	})
	assert.NoError(t, eg.Wait())
}

func TestMergerdCoverageRecords(t *testing.T) {
	tests := []struct {
		name        string
		input       *FileMergeResult
		wantRecords []*coveragedb.MergedCoverageRecord
	}{
		{
			name: "file doesn't exist",
			input: &FileMergeResult{
				FilePath: "deleted.c",
				MergeResult: &MergeResult{
					FileExists: false,
				},
			},
			wantRecords: nil,
		},
		{
			name: "two managers merge",
			input: &FileMergeResult{
				FilePath: "file.c",
				MergeResult: &MergeResult{
					FileExists: true,
					HitCounts: map[int]int64{
						1: 5,
						2: 7,
					},
					LineDetails: map[int][]*FileRecord{
						1: {
							{
								FilePath: "file.c",
								RepoCommit: RepoCommit{
									Repo:   "repo1",
									Commit: "commit1",
								},
								StartLine: 10,
								HitCount:  5,
								Manager:   "manager1",
							},
						},
						2: {
							{
								FilePath: "file.c",
								RepoCommit: RepoCommit{
									Repo:   "repo2",
									Commit: "commit2",
								},
								StartLine: 20,
								HitCount:  7,
								Manager:   "manager2",
							},
						},
					},
				},
			},
			wantRecords: []*coveragedb.MergedCoverageRecord{
				{
					Manager:  "*",
					FilePath: "file.c",
					FileData: &coveragedb.Coverage{
						Instrumented:      2,
						Covered:           2,
						LinesInstrumented: []int64{1, 2},
						HitCounts:         []int64{5, 7},
					},
				},
				{
					Manager:  "manager1",
					FilePath: "file.c",
					FileData: &coveragedb.Coverage{
						Instrumented:      1,
						Covered:           1,
						LinesInstrumented: []int64{1},
						HitCounts:         []int64{5},
					},
				},
				{
					Manager:  "manager2",
					FilePath: "file.c",
					FileData: &coveragedb.Coverage{
						Instrumented:      1,
						Covered:           1,
						LinesInstrumented: []int64{2},
						HitCounts:         []int64{7},
					},
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			gotRecords, gotFuncs := mergedCoverageRecords(test.input)
			sort.Slice(gotRecords, func(i, j int) bool {
				return gotRecords[i].Manager < gotRecords[j].Manager
			})
			assert.Equal(t, test.wantRecords, gotRecords, "records are not equal")
			assert.Equal(t, 0, len(gotFuncs), "no functions expected")
		})
	}
}

// nolint: lll
func TestAggregateStreamData(t *testing.T) {
	type Test struct {
		name              string
		workdir           string
		bqTable           string
		simpleAggregation string
		baseRepo          string
		baseCommit        string
		checkDetails      bool
	}
	tests := []Test{
		{
			name:              "aesni-intel_glue",
			workdir:           testsPath + "/aesni-intel_glue/test-workdir-covermerger",
			bqTable:           readFileOrFail(t, testsPath+"/aesni-intel_glue/bqTable.txt"),
			simpleAggregation: readFileOrFail(t, testsPath+"/aesni-intel_glue/merge_result.txt"),
			baseRepo:          "git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git",
			baseCommit:        "fe46a7dd189e25604716c03576d05ac8a5209743",
		},
		{
			name:    "code deleted",
			workdir: defaultTestWorkdir,
			bqTable: `timestamp,version,fuzzing_minutes,arch,build_id,manager,kernel_repo,kernel_branch,kernel_commit,file_path,func_name,sl,sc,el,ec,hit_count,inline,pc
samp_time,1,360,arch,b1,ci-mock,git://repo,master,commit1,delete_code.c,func1,2,0,2,-1,1,true,1`,
			simpleAggregation: `{
  "delete_code.c":
  {
    "HitCounts":{},
		"FileExists": true,
		"LineDetails":{}
  }
}`,
			baseRepo:     "git://repo",
			baseCommit:   "commit2",
			checkDetails: true,
		},
		{
			name:    "file deleted",
			workdir: defaultTestWorkdir,
			bqTable: `timestamp,version,fuzzing_minutes,arch,build_id,manager,kernel_repo,kernel_branch,kernel_commit,file_path,func_name,sl,sc,el,ec,hit_count,inline,pc
samp_time,1,360,arch,b1,ci-mock,git://repo,master,commit1,delete_file.c,func1,2,0,2,-1,1,true,1`,
			simpleAggregation: `{
  "delete_file.c":
  {
		"FileExists": false
  }
}`,
			baseRepo:     "git://repo",
			baseCommit:   "commit2",
			checkDetails: true,
		},
		{
			name:    "covered line changed",
			workdir: defaultTestWorkdir,
			bqTable: `timestamp,version,fuzzing_minutes,arch,build_id,manager,kernel_repo,kernel_branch,kernel_commit,file_path,func_name,sl,sc,el,ec,hit_count,inline,pc
samp_time,1,360,arch,b1,ci-mock,git://repo,master,commit1,change_line.c,func1,2,0,2,-1,1,true,1
samp_time,1,360,arch,b1,ci-mock,git://repo,master,commit1,change_line.c,func1,3,0,3,-1,1,true,1`,
			simpleAggregation: `{
  "change_line.c":
  {
		"HitCounts":{"3": 1},
		"FileExists": true,
		"LineDetails":
		{
			"3":
			[
				{
					"FilePath":"change_line.c",
					"FuncName":"func1",
					"Repo":"git://repo",
					"Commit":"commit1",
					"StartLine":3,
					"HitCount":1,
					"Manager":"ci-mock"
				}
			]
		}
  }
}`,
			baseRepo:     "git://repo",
			baseCommit:   "commit2",
			checkDetails: true,
		},
		{
			name:    "add line",
			workdir: defaultTestWorkdir,
			bqTable: `timestamp,version,fuzzing_minutes,arch,build_id,manager,kernel_repo,kernel_branch,kernel_commit,file_path,func_name,sl,sc,el,ec,hit_count,inline,pc
samp_time,1,360,arch,b1,ci-mock,git://repo,master,commit1,add_line.c,func1,2,0,2,-1,1,true,1`,
			simpleAggregation: `{
  "add_line.c":
  {
		"HitCounts":{"2": 1},
		"FileExists": true,
		"LineDetails":
		{
			"2":
			[
				{
					"FilePath":"add_line.c",
					"FuncName":"func1",
					"Repo":"git://repo",
					"Commit":"commit1",
					"StartLine":2,
					"HitCount":1,
					"Manager":"ci-mock"
				}
			]
		}
  }
}`,
			baseRepo:     "git://repo",
			baseCommit:   "commit2",
			checkDetails: true,
		},
		{
			name:    "instrumented lines w/o coverage are reported",
			workdir: defaultTestWorkdir,
			bqTable: `timestamp,version,fuzzing_minutes,arch,build_id,manager,kernel_repo,kernel_branch,kernel_commit,file_path,func_name,sl,sc,el,ec,hit_count,inline,pc
samp_time,1,360,arch,b1,ci-mock,git://repo,master,commit1,not_changed.c,func1,3,0,3,-1,0,true,1
samp_time,1,360,arch,b1,ci-mock,git://repo,master,commit2,not_changed.c,func1,4,0,4,-1,0,true,1`,
			simpleAggregation: `{
  "not_changed.c":
  {
		"HitCounts":{"3": 0, "4": 0},
		"FileExists": true,
		"LineDetails":
		{
			"3":
			[
				{
					"FilePath":"not_changed.c",
					"FuncName":"func1",
					"Repo":"git://repo",
					"Commit":"commit1",
					"StartLine":3,
					"HitCount":0,
					"Manager":"ci-mock"
				}
			],
			"4":
			[
				{
					"FilePath":"not_changed.c",
					"FuncName":"func1",
					"Repo":"git://repo",
					"Commit":"commit2",
					"StartLine":4,
					"HitCount":0,
					"Manager":"ci-mock"
				}
			]
		}
  }
}`,
			baseRepo:     "git://repo",
			baseCommit:   "commit2",
			checkDetails: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			mergeResultsCh := make(chan *FileMergeResult)
			doneCh := make(chan bool)
			go func() {
				aggregation := make(map[string]*MergeResult)
				for fmr := range mergeResultsCh {
					aggregation[fmr.FilePath] = fmr.MergeResult
				}
				if !test.checkDetails {
					ignoreLineDetailsInTest(aggregation)
				}
				var expectedAggregation map[string]*MergeResult
				assert.NoError(t, json.Unmarshal([]byte(test.simpleAggregation), &expectedAggregation))
				assert.Equal(t, expectedAggregation, aggregation)
				doneCh <- true
			}()
			assert.NoError(t, MergeCSVData(
				context.Background(),
				testConfig(test.baseRepo, test.baseCommit, test.workdir),
				strings.NewReader(test.bqTable),
				mergeResultsCh))
			close(mergeResultsCh)
			<-doneCh
		})
	}
}

func ignoreLineDetailsInTest(results map[string]*MergeResult) {
	for _, mr := range results {
		mr.LineDetails = nil
	}
}

type fileVersProviderMock struct {
	Workdir string
}

func (m *fileVersProviderMock) GetFileVersions(targetFilePath string, repoCommits ...RepoCommit,
) (FileVersions, error) {
	res := make(FileVersions)
	for _, repoCommit := range repoCommits {
		filePath := filepath.Join(m.Workdir, "repos", repoCommit.Commit, targetFilePath)
		if bytes, err := os.ReadFile(filePath); err == nil {
			res[repoCommit] = string(bytes)
		}
	}
	return res, nil
}

func readFileOrFail(t *testing.T, path string) string {
	absPath, err := filepath.Abs(path)
	assert.Nil(t, err)
	content, err := os.ReadFile(absPath)
	assert.Nil(t, err)
	return string(content)
}

func testConfig(repo, commit, workdir string) *Config {
	return &Config{
		Jobs:          2,
		skipRepoClone: true,
		Base: RepoCommit{
			Repo:   repo,
			Commit: commit,
		},
		FileVersProvider: &fileVersProviderMock{Workdir: workdir},
	}
}

func TestCheckedFuncName(t *testing.T) {
	tests := []struct {
		name  string
		input []string
		want  string
	}{
		{
			name: "empty input",
			want: "",
		},
		{
			name:  "single func",
			input: []string{"func1", "func1"},
			want:  "func1",
		},
		{
			name:  "multi names",
			input: []string{"", "", "", "func2", "func2", "func1", "func"},
			want:  "func2",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := bestFuncName(test.input)
			assert.Equal(t, test.want, got)
		})
	}
}
