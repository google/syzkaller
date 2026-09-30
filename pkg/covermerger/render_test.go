// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package covermerger

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const testCSVHeader = "timestamp,version,fuzzing_minutes,arch,build_id,manager,kernel_repo,kernel_branch," +
	"kernel_commit,file_path,func_name,sl,sc,el,ec,hit_count,inline,pc\n"

func TestMergeFileCSVData(t *testing.T) {
	config := testConfig("git://repo", "commit2", defaultTestWorkdir)
	csv := testCSVHeader +
		"samp_time,1,360,arch,b1,ci-mock,git://repo,master,commit1,add_line.c,func1,2,0,2,-1,1,true,1"
	mr, err := mergeFileCSVData(context.Background(), config, strings.NewReader(csv), "add_line.c")
	require.NoError(t, err)
	require.NotNil(t, mr)
	require.True(t, mr.FileExists)
	require.Equal(t, map[int]int64{2: 1}, mr.HitCounts)
}

func TestMergeFileCSVDataNoRecords(t *testing.T) {
	config := testConfig("git://repo", "commit2", defaultTestWorkdir)
	mr, err := mergeFileCSVData(context.Background(), config, strings.NewReader(testCSVHeader), "add_line.c")
	require.Error(t, err)
	require.Nil(t, mr)
}
