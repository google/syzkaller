// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/cover"
	gcsmocks "github.com/google/syzkaller/pkg/gcs/mocks"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/vcs"
	"github.com/google/syzkaller/sys/targets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

type dashapiMock struct {
	mock.Mock
}

func (dm *dashapiMock) BuilderPoll(manager string) (*dashapi.BuilderPollResp, error) {
	args := dm.Called(manager)
	return args.Get(0).(*dashapi.BuilderPollResp), args.Error(1)
}

// We don't care about the methods below for now.
func (dm *dashapiMock) ReportBuildError(req *dashapi.BuildErrorReq) error { return nil }
func (dm *dashapiMock) UploadBuild(build *dashapi.Build) error            { return nil }
func (dm *dashapiMock) LogError(name, msg string, args ...interface{})    {}
func (dm *dashapiMock) CommitPoll() (*dashapi.CommitPollResp, error)      { return nil, nil }
func (dm *dashapiMock) UploadCommits(commits []dashapi.Commit) error      { return nil }

func TestManagerPollCommits(t *testing.T) {
	// Mock a repository.
	baseDir := t.TempDir()
	repo := vcs.CreateTestRepo(t, baseDir, "")
	var lastCommit *vcs.Commit
	for _, title := range []string{
		"unrelated commit one",
		"commit1 title",
		"unrelated commit two",
		"commit3 title",
		`title with fix

Reported-by: foo+abcd000@bar.com`,
		"unrelated commit three",
	} {
		lastCommit = repo.CommitChange(title)
	}

	vcsRepo, err := vcs.NewRepo(targets.TestOS, targets.TestArch64, baseDir, vcs.OptPrecious)
	if err != nil {
		t.Fatal(err)
	}

	mock := new(dashapiMock)
	mgr := Manager{
		name:   "test-manager",
		dash:   mock,
		repo:   vcsRepo,
		mgrcfg: &ManagerConfig{},
	}

	// Mock BuilderPoll().
	commits := []string{
		"commit1 title",
		"commit2 title",
		"commit3 title",
		"commit4 title",
	}
	// Let's trigger sampling as well.
	for i := 0; i < 100; i++ {
		commits = append(commits, fmt.Sprintf("test%d", i))
	}
	mock.On("BuilderPoll", "test-manager").Return(&dashapi.BuilderPollResp{
		PendingCommits: commits,
		ReportEmail:    "foo@bar.com",
	}, nil)

	matches, fixCommits, err := mgr.pollCommits(lastCommit.Hash)
	if err != nil {
		t.Fatal(err)
	}

	foundCommits := map[string]bool{}
	// Call it several more times to catch all commits.
	for i := 0; i < 100; i++ {
		for _, name := range matches {
			foundCommits[name] = true
		}
		matches, _, err = mgr.pollCommits(lastCommit.Hash)
		if err != nil {
			t.Fatal(err)
		}
	}

	var foundCommitsSlice []string
	for title := range foundCommits {
		foundCommitsSlice = append(foundCommitsSlice, title)
	}
	assert.ElementsMatch(t, foundCommitsSlice, []string{
		"commit1 title", "commit3 title",
	})
	assert.Len(t, fixCommits, 1)
	commit := fixCommits[0]
	assert.Equal(t, commit.Title, "title with fix")
	assert.ElementsMatch(t, commit.BugIDs, []string{"abcd000"})
}

func TestUploadCoverJSONLToGCS(t *testing.T) {
	tests := []struct {
		name string

		inputJSONL      string
		inputNameSuffix string

		inputCompress bool
		inputPublish  bool

		wantGCSFileName    string
		wantGCSFileContent string
		wantCompressed     bool
		wantPublish        bool
		wantError          string
	}{
		{
			name:               "upload single object",
			inputJSONL:         "{}",
			wantGCSFileName:    "test-bucket/test-namespace/mgr-name.jsonl",
			wantGCSFileContent: "{}\n",
		},
		{
			name:               "upload single object, compress",
			inputJSONL:         "{}",
			inputCompress:      true,
			wantGCSFileName:    "test-bucket/test-namespace/mgr-name.jsonl",
			wantGCSFileContent: "{}\n",
			wantCompressed:     true,
		},
		{
			name:               "upload single object, publish",
			inputJSONL:         "{}",
			inputPublish:       true,
			wantGCSFileName:    "test-bucket/test-namespace/mgr-name.jsonl",
			wantGCSFileContent: "{}\n",
			wantPublish:        true,
		},
		{
			name:               "upload single object, unique name",
			inputJSONL:         "{}",
			inputNameSuffix:    "-suffix",
			wantGCSFileName:    "test-bucket/test-namespace/mgr-name-suffix.jsonl",
			wantGCSFileContent: "{}\n",
		},

		{
			name:            "upload single object, error",
			inputJSONL:      "{",
			wantGCSFileName: "test-bucket/test-namespace/mgr-name.jsonl",
			wantError:       "callback: cover.ProgramCoverage: unexpected EOF",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			httpServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				w.Write([]byte(test.inputJSONL))
			}))
			defer httpServer.Close()

			testSetverAddrPort, _ := strings.CutPrefix(httpServer.URL, "http://")
			mgr := Manager{
				name: "mgr-name",
				managercfg: &mgrconfig.Config{
					HTTP:  testSetverAddrPort,
					Cover: true,
				},
				mgrcfg: &ManagerConfig{
					DashboardClient: "test-namespace",
				},
			}

			gcsMock := gcsmocks.NewClient(t)
			gotBytes := mockWriteCloser{}

			gcsMock.On("FileWriter", test.wantGCSFileName, "", "").
				Return(&gotBytes, nil).Once()
			gcsMock.On("Close").Return(nil).Once()
			if test.wantPublish {
				gcsMock.On("Publish", test.wantGCSFileName).
					Return(nil).Once()
			}
			err := mgr.uploadCoverJSONLToGCS(context.Background(), gcsMock,
				"/teststream&jsonl=1",
				"gs://test-bucket",
				uploadOptions{
					nameSuffix: test.inputNameSuffix,
					publish:    test.inputPublish,
					compress:   test.inputCompress,
				},
				func(w io.Writer, dec *json.Decoder) error {
					var v any
					if err := dec.Decode(&v); err != nil {
						return fmt.Errorf("cover.ProgramCoverage: %w", err)
					}
					if err := cover.WriteJSLine(w, &v); err != nil {
						return fmt.Errorf("cover.WriteJSLine: %w", err)
					}
					return nil
				})
			if test.wantError != "" {
				assert.Equal(t, test.wantError, err.Error())
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, 1, gotBytes.closedTimes)
			if test.wantCompressed {
				gzReader, err := gzip.NewReader(&gotBytes.buf)
				assert.NoError(t, err)
				defer gzReader.Close()
				plainBytes := mockWriteCloser{}
				_, err = io.Copy(&plainBytes, gzReader)
				assert.NoError(t, err)
				gotBytes = plainBytes
			}
			assert.Equal(t, test.wantGCSFileContent, gotBytes.buf.String())
		})
	}
}

type mockWriteCloser struct {
	buf         bytes.Buffer
	closedTimes int
}

func (m *mockWriteCloser) Write(p []byte) (n int, err error) {
	return m.buf.Write(p)
}

func (m *mockWriteCloser) Close() error {
	m.closedTimes++
	return nil
}
