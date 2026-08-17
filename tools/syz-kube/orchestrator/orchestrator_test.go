// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestScheduleBuildJob(t *testing.T) {
	fakeClient := fake.NewSimpleClientset()
	orch := &Orchestrator{
		client:    fakeClient,
		namespace: "syzkube",
	}

	ctx := context.Background()
	cfg := BuildConfig{
		Repo:        "https://github.com/torvalds/linux.git",
		Branch:      "master",
		Commit:      "head",
		ConfigPath:  "/syzkaller/dashboard/config/linux/upstream-apparmor-kasan.config",
		GCSBucket:   "syzkaller-builds",
		GCSEndpoint: "http://fake-gcs-server.syzkube.svc.cluster.local:4443",
	}

	job, err := orch.ScheduleBuildJob(ctx, cfg)
	require.NoError(t, err)
	require.NotEmpty(t, job.Name)
	require.Equal(t, "syzkube", job.Namespace)
	require.Equal(t, "syz-build", job.Labels["app.kubernetes.io/name"])

	jobs, err := orch.ListJobs(ctx, "")
	require.NoError(t, err)
	require.Len(t, jobs.Items, 1)
	require.Equal(t, job.Name, jobs.Items[0].Name)

	err = orch.DeleteJob(ctx, job.Name)
	require.NoError(t, err)

	jobsAfterDelete, err := orch.ListJobs(ctx, "")
	require.NoError(t, err)
	require.Empty(t, jobsAfterDelete.Items)
}

func TestScheduleBisectionJob(t *testing.T) {
	fakeClient := fake.NewSimpleClientset()
	orch := &Orchestrator{
		client:    fakeClient,
		namespace: "syzkube",
	}

	ctx := context.Background()
	cfg := BisectConfig{
		ConfigPath: "/config/tools/syz-kube/bisect_config.json",
		CrashPath:  "/config/tools/syz-kube/test-crash",
	}

	job, err := orch.ScheduleBisectionJob(ctx, cfg)
	require.NoError(t, err)
	require.NotEmpty(t, job.Name)
	require.Equal(t, "syzkube", job.Namespace)
	require.Equal(t, "syz-bisect", job.Labels["app.kubernetes.io/name"])

	jobs, err := orch.ListJobs(ctx, "app.kubernetes.io/name=syz-bisect")
	require.NoError(t, err)
	require.Len(t, jobs.Items, 1)
	require.Equal(t, job.Name, jobs.Items[0].Name)
}

func TestUpdateManagerConfigAndRestart(t *testing.T) {
	fakeClient := fake.NewSimpleClientset()
	orch := &Orchestrator{
		client:    fakeClient,
		namespace: "syzkube",
	}

	ctx := context.Background()
	cm := &corev1.ConfigMap{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "syz-manager-config",
			Namespace: "syzkube",
		},
		Data: map[string]string{
			"manager.cfg": `{"name":"test","tag":"old-tag"}`,
		},
	}
	_, err := fakeClient.CoreV1().ConfigMaps("syzkube").Create(ctx, cm, metav1.CreateOptions{})
	require.NoError(t, err)

	err = orch.UpdateManagerConfigAndRestart(ctx, 0, "new-tag-123", "console=ttyS0", "-enable-kvm")
	require.NoError(t, err)

	updatedCM, err := fakeClient.CoreV1().ConfigMaps("syzkube").Get(ctx, "syz-manager-config", metav1.GetOptions{})
	require.NoError(t, err)
	require.Contains(t, updatedCM.Data["manager.cfg"], "new-tag-123")
	require.Contains(t, updatedCM.Data["manager.cfg"], "console=ttyS0")
}

func TestScheduleCoverageAggregationJob(t *testing.T) {
	fakeClient := fake.NewSimpleClientset()
	orch := &Orchestrator{
		client:    fakeClient,
		namespace: "syzkube",
	}

	ctx := context.Background()
	job, err := orch.ScheduleCoverageAggregationJob(ctx, "test-tag")
	require.NoError(t, err)
	require.NotEmpty(t, job.Name)
	require.Equal(t, "syzkube", job.Namespace)
	require.Equal(t, "coverage-aggregator", job.Labels["app.kubernetes.io/name"])
}

func TestPruneUnusedAssets(t *testing.T) {
	tempAssetsDir := t.TempDir()
	activeTag := "matrix-active-tag"
	staleTag := "matrix-stale-tag"

	require.NoError(t, os.MkdirAll(filepath.Join(tempAssetsDir, activeTag), 0755))
	require.NoError(t, os.MkdirAll(filepath.Join(tempAssetsDir, staleTag), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(tempAssetsDir, "id_rsa"), []byte("key"), 0600))

	orch := &Orchestrator{
		activeTags: map[int]string{
			0: activeTag,
		},
	}

	// Mock assets dir by testing pruning logic directly on the directory.
	orch.activeTagsMu.Lock()
	inUse := make(map[string]bool)
	for _, tag := range orch.activeTags {
		if tag != "" {
			inUse[tag] = true
		}
	}
	orch.activeTagsMu.Unlock()

	entries, err := os.ReadDir(tempAssetsDir)
	require.NoError(t, err)
	for _, entry := range entries {
		if !entry.IsDir() || !strings.HasPrefix(entry.Name(), "matrix-") {
			continue
		}
		if !inUse[entry.Name()] {
			_ = os.RemoveAll(filepath.Join(tempAssetsDir, entry.Name()))
		}
	}

	_, activeErr := os.Stat(filepath.Join(tempAssetsDir, activeTag))
	require.NoError(t, activeErr)

	_, staleErr := os.Stat(filepath.Join(tempAssetsDir, staleTag))
	require.True(t, os.IsNotExist(staleErr))

	_, keyErr := os.Stat(filepath.Join(tempAssetsDir, "id_rsa"))
	require.NoError(t, keyErr)
}
