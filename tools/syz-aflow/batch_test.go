// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/google/syzkaller/pkg/aflow/ai"
	"github.com/google/syzkaller/pkg/aflow/trajectory"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/stretchr/testify/require"
)

func TestValidateBatchMode(t *testing.T) {
	flow := string(ai.WorkflowSeedGenFileLine)
	tests := []struct {
		name    string
		isBatch bool
		args    RunnerArgs
		wantErr string
	}{
		{
			name: "valid single",
			args: RunnerArgs{FlowName: "my-flow", Parallel: 1},
		},
		{
			name:    "valid batch",
			isBatch: true,
			args:    RunnerArgs{FlowName: flow, Workdir: "workdir", Parallel: 4},
		},
		{
			name:    "single rejects parallel",
			args:    RunnerArgs{FlowName: "my-flow", Parallel: 2},
			wantErr: "-parallel can only be used in batch execution",
		},
		{
			name:    "batch unsupported workflow",
			isBatch: true,
			args:    RunnerArgs{FlowName: "other-flow", Workdir: "workdir", Parallel: 4},
			wantErr: "batch execution is currently only supported for",
		},
		{
			name:    "batch missing workdir",
			isBatch: true,
			args:    RunnerArgs{FlowName: flow, Parallel: 4},
			wantErr: "-workdir must be specified",
		},
		{
			name:    "batch rejects output files",
			isBatch: true,
			args:    RunnerArgs{FlowName: flow, Workdir: "workdir", HTML: "traj.html", Parallel: 4},
			wantErr: "-html and -output cannot be used in batch execution",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := validateBatchMode(tt.isBatch, tt.args)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestClassifyResultState(t *testing.T) {
	require.Equal(t, stateError, classifyResultState(nil, errors.New("some error")))
	require.Equal(t, stateSuccess, classifyResultState(map[string]any{"Success": true}, nil))
	require.Equal(t, stateGiveUp, classifyResultState(map[string]any{"GiveUp": true}, nil))
	require.Equal(t, stateGiveUp, classifyResultState(map[string]any{"Success": false, "GiveUp": false}, nil))
	require.Equal(t, stateGiveUp, classifyResultState(nil, nil))
}

func TestFindTaskFiles(t *testing.T) {
	tempDir := t.TempDir()
	for _, name := range []string{"task_b.json", "task_a.json"} {
		require.NoError(t, osutil.WriteJSON(filepath.Join(tempDir, name), map[string]any{}))
	}
	require.NoError(t, osutil.WriteFile(filepath.Join(tempDir, "not_task.txt"), []byte("txt")))

	// Test passing directory.
	tasks, isBatch, err := findTaskFiles(tempDir)
	require.NoError(t, err)
	require.True(t, isBatch)
	require.Equal(t, []batchTask{
		{ID: "task_a", Path: filepath.Join(tempDir, "task_a.json")},
		{ID: "task_b", Path: filepath.Join(tempDir, "task_b.json")},
	}, tasks)

	// Test passing single file.
	singleTask, isBatch, err := findTaskFiles(filepath.Join(tempDir, "task_a.json"))
	require.NoError(t, err)
	require.False(t, isBatch)
	require.Equal(t, []batchTask{{ID: "task_a", Path: filepath.Join(tempDir, "task_a.json")}}, singleTask)

	// Test nonexistent path.
	_, _, err = findTaskFiles(filepath.Join(tempDir, "nonexistent.json"))
	require.Error(t, err)
}

func TestBatchRunnerIsCompleted(t *testing.T) {
	runner := &Runner{workdir: t.TempDir()}
	for _, state := range batchStates {
		require.NoError(t, runner.saveResult(batchResult{ID: "task_" + state, State: state}, nil))
	}

	completed, err := runner.completedTaskIDs()
	require.NoError(t, err)
	require.Equal(t, map[string]bool{
		"task_success": true,
		"task_giveup":  true,
		"task_error":   true,
	}, completed)
}

func TestAppendOrUpdateSpan(t *testing.T) {
	var spans []*trajectory.Span

	// Add span with Seq 0.
	s0 := &trajectory.Span{Seq: 0, Name: "start_0"}
	spans = appendOrUpdateSpan(spans, s0)
	require.Equal(t, 1, len(spans))
	require.Equal(t, s0, spans[0])

	// Add span with Seq 2 (out of order, skipping Seq 1).
	s2 := &trajectory.Span{Seq: 2, Name: "start_2"}
	spans = appendOrUpdateSpan(spans, s2)
	require.Equal(t, 3, len(spans))
	require.Equal(t, s0, spans[0])
	require.Nil(t, spans[1])
	require.Equal(t, s2, spans[2])

	// Fill in span with Seq 1.
	s1 := &trajectory.Span{Seq: 1, Name: "start_1"}
	spans = appendOrUpdateSpan(spans, s1)
	require.Equal(t, 3, len(spans))
	require.Equal(t, s0, spans[0])
	require.Equal(t, s1, spans[1])
	require.Equal(t, s2, spans[2])

	// Update span with Seq 0 on finish.
	s0Updated := &trajectory.Span{Seq: 0, Name: "finish_0"}
	spans = appendOrUpdateSpan(spans, s0Updated)
	require.Equal(t, 3, len(spans))
	require.Equal(t, s0Updated, spans[0])
	require.Equal(t, s1, spans[1])
	require.Equal(t, s2, spans[2])
}
