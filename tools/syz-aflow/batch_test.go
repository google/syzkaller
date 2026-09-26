// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/google/syzkaller/pkg/aflow/ai"
	"github.com/google/syzkaller/pkg/aflow/trajectory"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/stretchr/testify/assert"
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
	require.Equal(t, stateUnreached, classifyResultState(map[string]any{"Success": false, "GiveUp": false}, nil))
	require.Equal(t, stateUnreached, classifyResultState(nil, nil))
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

func TestPrepareBatchTasks(t *testing.T) {
	tests := []struct {
		name string
		// Existing trajectory files, relative to the trajectories directory.
		files []string
		tasks []string
		// The tasks expected to be resumed first and the ones expected to follow them.
		wantResumed []string
		wantRest    []string
		// The trajectory files expected to be gone afterwards.
		wantRemoved []string
	}{
		{
			name:     "empty workdir",
			tasks:    []string{"task_1", "task_2"},
			wantRest: []string{"task_1", "task_2"},
		},
		{
			name: "completed tasks are skipped",
			files: []string{
				"success/task_1.json",
				"giveup/task_2.json",
				"unreached/task_3.json",
				"error/task_4.json",
				// Not a result file, so task_5 is still pending.
				"success/task_5.html",
			},
			tasks:    []string{"task_1", "task_2", "task_3", "task_4", "task_5"},
			wantRest: []string{"task_5"},
		},
		{
			name: "aborted tasks come first",
			files: []string{
				"in_progress/task_2.log",
				"in_progress/task_4.html",
				"in_progress/task_4.log",
				// Only result files mark a task as completed.
				"in_progress/task_5.json",
			},
			tasks:       []string{"task_1", "task_2", "task_3", "task_4", "task_5"},
			wantResumed: []string{"task_2", "task_4"},
			wantRest:    []string{"task_1", "task_3", "task_5"},
		},
		{
			name: "stale files of completed tasks are removed",
			files: []string{
				"success/task_1.json",
				"in_progress/task_1.html",
				"in_progress/task_1.log",
				"in_progress/task_2.log",
				// The task is no longer in the list, but its files must be kept.
				"in_progress/task_3.log",
			},
			tasks:       []string{"task_1", "task_2"},
			wantResumed: []string{"task_2"},
			wantRemoved: []string{"in_progress/task_1.html", "in_progress/task_1.log"},
		},
		{
			name:        "dots in task IDs",
			files:       []string{"in_progress/net.ipv4.log", "success/net.ipv6.json"},
			tasks:       []string{"net.ipv4", "net.ipv6"},
			wantResumed: []string{"net.ipv4"},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runner := &Runner{workdir: t.TempDir()}
			for _, file := range test.files {
				path := filepath.Join(runner.workdir, "trajectories", file)
				require.NoError(t, osutil.MkdirAll(filepath.Dir(path)))
				require.NoError(t, osutil.WriteFile(path, []byte("data")))
			}
			var tasks []batchTask
			for _, id := range test.tasks {
				tasks = append(tasks, batchTask{ID: id})
			}

			ordered, resumed, err := runner.prepareBatchTasks(tasks)
			require.NoError(t, err)
			require.Equal(t, len(test.wantResumed), resumed)
			assert.ElementsMatch(t, test.wantResumed, taskIDsOf(ordered[:resumed]))
			assert.ElementsMatch(t, test.wantRest, taskIDsOf(ordered[resumed:]))

			for _, file := range test.files {
				path := filepath.Join(runner.workdir, "trajectories", file)
				if slices.Contains(test.wantRemoved, file) {
					assert.NoFileExists(t, path)
				} else {
					assert.FileExists(t, path)
				}
			}
		})
	}
}

func TestPrepareBatchTasksRandomizes(t *testing.T) {
	runner := &Runner{workdir: t.TempDir()}
	var tasks []batchTask
	for i := range 10 {
		tasks = append(tasks, batchTask{ID: fmt.Sprintf("task_%d", i)})
	}
	orders := map[string]bool{}
	for range 20 {
		ordered, _, err := runner.prepareBatchTasks(tasks)
		require.NoError(t, err)
		orders[strings.Join(taskIDsOf(ordered), " ")] = true
	}
	assert.Greater(t, len(orders), 1, "the task order must be randomized")
}

func TestSaveResult(t *testing.T) {
	runner := &Runner{workdir: t.TempDir()}
	inProgressDir := filepath.Join(runner.workdir, "trajectories", stateInProgress)
	require.NoError(t, osutil.MkdirAll(inProgressDir))
	require.NoError(t, osutil.WriteFile(filepath.Join(inProgressDir, "task_1.html"), []byte("html")))
	require.NoError(t, osutil.WriteFile(filepath.Join(inProgressDir, "task_1.log"), []byte("log")))

	require.NoError(t, runner.saveResult(batchResult{ID: "task_1", State: stateSuccess}, nil))

	// The in-progress files must be gone and the log must be preserved in the final directory.
	assert.NoFileExists(t, runner.targetPath(stateInProgress, "task_1", ".html"))
	assert.NoFileExists(t, runner.targetPath(stateInProgress, "task_1", ".log"))
	assert.FileExists(t, runner.targetPath(stateSuccess, "task_1", ".json"))
	assert.FileExists(t, runner.targetPath(stateSuccess, "task_1", ".html"))
	logData, err := os.ReadFile(runner.targetPath(stateSuccess, "task_1", ".log"))
	require.NoError(t, err)
	assert.Equal(t, "log", string(logData))
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

func taskIDsOf(tasks []batchTask) []string {
	var ids []string
	for _, task := range tasks {
		ids = append(ids, task.ID)
	}
	return ids
}
