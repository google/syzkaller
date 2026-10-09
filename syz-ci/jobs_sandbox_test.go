// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/syzkaller/pkg/build"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/sys/targets"
	"github.com/stretchr/testify/require"
)

func TestJobSandbox(t *testing.T) {
	osutil.RequireSandbox(t)
	workdir := t.TempDir()
	kernel, commit := build.MakeTestKernelRepo(t, filepath.Join(workdir, "kernel"))
	image := filepath.Join(workdir, "image")
	require.NoError(t, osutil.WriteFile(image, nil))

	cfg := &Config{SyzkallerRepo: kernel.Dir}
	mgr, err := createManager(filepath.Join(workdir, "manager"), cfg, &ManagerConfig{
		Name:      "test",
		Repo:      kernel.Dir,
		Branch:    "master",
		Userspace: image,
		managercfg: &mgrconfig.Config{
			Name:    "test",
			Type:    "qemu",
			VM:      []byte("{}"),
			Derived: mgrconfig.Derived{TargetOS: targets.Linux, TargetArch: targets.AMD64, TargetVMArch: targets.AMD64},
		},
	}, false)
	require.NoError(t, err)
	_, err = mgr.repo.Poll(mgr.mgrcfg.Repo, mgr.mgrcfg.Branch)
	require.NoError(t, err)

	key := filepath.Join(workdir, "manager", "key")
	require.NoError(t, os.WriteFile(key, []byte("secret"), 0600))
	t.Setenv("SYZ_TEST_FORBIDDEN", key)

	jp := &JobProcessor{
		JobManager: &JobManager{cfg: cfg},
		baseDir:    filepath.Join(workdir, "jobs"),
	}
	resp := jp.process(&Job{
		mgr: mgr,
		req: &dashapi.JobPollResp{
			ID:              "job",
			Type:            dashapi.JobTestPatch,
			Manager:         mgr.name,
			KernelRepo:      kernel.Dir,
			KernelBranch:    "master",
			KernelConfig:    []byte("CONFIG_FOO=y\n"),
			SyzkallerCommit: commit,
			Patch:           []byte(build.TestKernelPatch),
		},
	})
	// TODO: mock instance.Env / VM testing in syz-ci so jp.process can succeed end-to-end.
	// Currently it runs all git and kernel build steps and only fails when env.Test tries to boot VMs.
	require.Contains(t, string(resp.Error), "syzkaller build log")
	require.Equal(t, commit, resp.Build.KernelCommit)
	require.Contains(t, string(resp.Build.KernelConfig), "CONFIG_OLDCONFIG=y")
	require.FileExists(t, filepath.Join(jp.baseDir, targets.Linux, "kernel", ".git", "objects", "info", "alternates"))
}
