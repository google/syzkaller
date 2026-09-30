// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package cover

import (
	"context"
	"strings"
	"testing"

	"github.com/google/syzkaller/pkg/covermerger"
	"github.com/stretchr/testify/require"
)

const testCSVHeader = "timestamp,version,fuzzing_minutes,arch,build_id,manager,kernel_repo,kernel_branch," +
	"kernel_commit,file_path,func_name,sl,sc,el,ec,hit_count,inline,pc\n"

// sameFileVersProvider returns the same file content for every commit.
type sameFileVersProvider struct {
	content string
}

func (p *sameFileVersProvider) GetFileVersions(targetFilePath string, repoCommits ...covermerger.RepoCommit,
) (covermerger.FileVersions, error) {
	res := make(covermerger.FileVersions)
	for _, rc := range repoCommits {
		res[rc] = p.content
	}
	return res, nil
}

func testMergeConfig() *covermerger.Config {
	return &covermerger.Config{
		Jobs:             1,
		Base:             covermerger.RepoCommit{Repo: "git://repo", Commit: "commit2"},
		FileVersProvider: &sameFileVersProvider{content: "line1\nline2\nline3\n"},
	}
}

func TestMergeFileCSVData(t *testing.T) {
	csv := testCSVHeader +
		"samp_time,1,360,arch,b1,ci-mock,git://repo,master,commit1,file.c,func1,2,0,2,-1,1,true,1"
	mr, err := mergeFileCSVData(context.Background(), testMergeConfig(), strings.NewReader(csv), "file.c")
	require.NoError(t, err)
	require.NotNil(t, mr)
	require.True(t, mr.FileExists)
	require.Equal(t, map[int]int64{2: 1}, mr.HitCounts)
}

func TestMergeFileCSVDataNoRecords(t *testing.T) {
	mr, err := mergeFileCSVData(context.Background(), testMergeConfig(), strings.NewReader(testCSVHeader), "file.c")
	require.Error(t, err)
	require.Nil(t, mr)
}
