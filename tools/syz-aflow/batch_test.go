// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"path/filepath"
	"slices"
	"testing"

	"github.com/google/syzkaller/pkg/osutil"
	"github.com/stretchr/testify/require"
)

func TestFindTaskFiles(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"task_b.json", "task_a.json", "not_task.txt"} {
		require.NoError(t, osutil.WriteFile(filepath.Join(dir, name), []byte("{}")))
	}

	tasks, isBatch, err := findTaskFiles(dir)
	require.NoError(t, err)
	require.True(t, isBatch)
	require.Equal(t, []batchTask{
		{ID: "task_a", Path: filepath.Join(dir, "task_a.json")},
		{ID: "task_b", Path: filepath.Join(dir, "task_b.json")},
	}, tasks)

	tasks, isBatch, err = findTaskFiles(filepath.Join(dir, "task_a.json"))
	require.NoError(t, err)
	require.False(t, isBatch)
	require.Equal(t, []batchTask{{ID: "task_a", Path: filepath.Join(dir, "task_a.json")}}, tasks)
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
			name: "completed tasks are skipped",
			files: []string{
				"success/task_1.json",
				"giveup/task_2.json",
				"error/task_3.json",
				// Not a result file, so task_4 is still pending.
				"success/task_4.html",
			},
			tasks:    []string{"task_1", "task_2", "task_3", "task_4"},
			wantRest: []string{"task_4"},
		},
		{
			name: "aborted tasks come first",
			files: []string{
				"in_progress/task_2.html",
				"in_progress/net.ipv4.html",
				// Only result files mark a task as completed.
				"in_progress/task_3.json",
			},
			tasks:       []string{"task_1", "task_2", "task_3", "net.ipv4"},
			wantResumed: []string{"task_2", "net.ipv4"},
			wantRest:    []string{"task_1", "task_3"},
		},
		{
			name: "stale files of completed tasks are removed",
			files: []string{
				"success/task_1.json",
				"in_progress/task_1.html",
				"in_progress/task_2.html",
				// The task is no longer in the list, but its files must be kept.
				"in_progress/task_3.html",
			},
			tasks:       []string{"task_1", "task_2"},
			wantResumed: []string{"task_2"},
			wantRemoved: []string{"in_progress/task_1.html"},
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
			require.ElementsMatch(t, test.wantResumed, taskIDsOf(ordered[:resumed]))
			require.ElementsMatch(t, test.wantRest, taskIDsOf(ordered[resumed:]))

			for _, file := range test.files {
				path := filepath.Join(runner.workdir, "trajectories", file)
				if slices.Contains(test.wantRemoved, file) {
					require.NoFileExists(t, path)
				} else {
					require.FileExists(t, path)
				}
			}
		})
	}
}

func TestSaveResult(t *testing.T) {
	runner := &Runner{workdir: t.TempDir()}
	inProgressHTML := runner.taskPath(stateInProgress, "task_1", ".html")
	require.NoError(t, osutil.MkdirAll(filepath.Dir(inProgressHTML)))
	require.NoError(t, osutil.WriteFile(inProgressHTML, []byte("html")))

	require.NoError(t, runner.saveResult(batchResult{ID: "task_1", State: stateSuccess}, nil))

	require.NoFileExists(t, inProgressHTML)
	require.FileExists(t, runner.taskPath(stateSuccess, "task_1", ".html"))
	// The saved result must make the task completed.
	ordered, _, err := runner.prepareBatchTasks([]batchTask{{ID: "task_1"}})
	require.NoError(t, err)
	require.Empty(t, ordered)
}

func taskIDsOf(tasks []batchTask) []string {
	var ids []string
	for _, task := range tasks {
		ids = append(ids, task.ID)
	}
	return ids
}
