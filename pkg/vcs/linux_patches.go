// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vcs

import (
	"fmt"
	"slices"
)

// BackportCommit describes a fix commit that must be cherry-picked to an older
// kernel revision in order to enable kernel build / boot.
type BackportCommit struct {
	// Backport is only applied if the commit is reachable from HEAD.
	GuiltyHash string `json:"guilty_hash"`
	// The hash of the commit to cherry-pick.
	FixHash string `json:"fix_hash"`
	// The field is only intended to make config files less cryptic.
	Comment string `json:"comment"`
}

// linuxFixBackports() cherry-picks the commits necessary to compile/run older Linux kernel releases.
func linuxFixBackports(repo *gitRepo, extraCommits ...BackportCommit) error {
	_, err := BackportCommits(repo,
		append(
			slices.Clone(pickLinuxCommits),
			extraCommits...,
		),
		defaultLinuxRepo,
	)
	return err
}

// BackportCommits conditionally cherry-picks the given commits into the repository.
// A commit is only cherry-picked if its GuiltyHash is present (if specified)
// and a commit with the same original title is not already present.
func BackportCommits(repo Repo, commits []BackportCommit, remoteRepoURL string) (bool, error) {
	applied := false
	for _, info := range commits {
		if info.GuiltyHash != "" {
			contains, err := repo.Contains(info.GuiltyHash)
			if err != nil {
				return applied, fmt.Errorf("failed to check if %s is present: %w", info.GuiltyHash, err)
			}
			if !contains {
				// There's no reason to backport a fix.
				continue
			}
		}
		if remoteRepoURL != "" {
			err := repo.fetchRemote(remoteRepoURL, info.FixHash)
			if err != nil {
				return applied, fmt.Errorf("failed to fetch fix commit %s: %w", info.FixHash, err)
			}
		}
		fixCommitOrig, err := repo.Commit(info.FixHash)
		if err != nil {
			return applied, fmt.Errorf("fix commit %s not found: %w", info.FixHash, err)
		}
		fixCommit, err := repo.GetCommitByTitle(fixCommitOrig.Title)
		if err != nil {
			return applied, err
		}
		if fixCommit != nil {
			// The fix is already present.
			continue
		}
		err = repo.cherryPick(info.FixHash)
		if err != nil {
			return applied, err
		}
		applied = true
	}
	return applied, nil
}

var pickLinuxCommits = []BackportCommit{
	{
		// Compiling v4.6..v5.11 with a modern objtool, w/o this patch, results in the
		// following issue, when compiling with clang:
		// arch/x86/entry/thunk_64.o: warning: objtool: missing symbol table
		// We don't bisect that far back with neither clang nor gcc, so this should be fine:
		// Title: objtool: Don't fail on missing symbol table
		FixHash: `1d489151e9f9d1647110277ff77282fe4d96d09b`,
	},
	{
		// With newer compiler versions, kernel compilation fails with:
		// subcmd-util.h:56:23: error: pointer may be used after ‘realloc’ [-Werror=use-after-free]
		// 56 |                 ret = realloc(ptr, size);
		// The guilty commit is from 2015, we don't bisect that far.
		// Title: libsubcmd: Fix use-after-free for realloc(..., 0)
		FixHash: `52a9dab6d892763b2a8334a568bd4e2c1a6fde66`,
	},
	{
		// A number of old releases fail with KASAN: use-after-free in task_active_pid_ns.
		// The problem was actually present so long ago that we do not need to check whether
		// the guilty commit is present. We don't bisect that back (v2.*) anyway.
		// Title: pid: take a reference when initializing `cad_pid`
		FixHash: `0711f0d7050b9e07c44bc159bbc64ac0a1022c7f`,
	},
	{
		// Fixes the following error:
		// check.c:2865:58: error: '%d' directive output may be truncated writing between 1 and
		// 10 bytes into a region of size 9 [-Werror=format-truncation=]
		// Title: objtool: Fix truncated string warning
		GuiltyHash: `db2b0c5d7b6f19b3c2cab08c531b65342eb5252b`,
		FixHash:    `82880283d7fcd0a1d20964a56d6d1a5cc0df0713`,
	},
	{
		// Fixes `boot failed: WARNING in kvm_wait`.
		// Title: x86/kvm: Fix broken irq restoration in kvm_wait
		GuiltyHash: `997acaf6b4b59c6a9c259740312a69ea549cc684`,
		FixHash:    `f4e61f0c9add3b00bd5f2df3c814d688849b8707`,
	},
	{
		// Fixes `error: implicit declaration of function 'acpi_mps_check'`.
		// Title: x86/setup: Explicitly include acpi.h
		GuiltyHash: `342f43af70dbc74f8629381998f92c060e1763a2`,
		FixHash:    `ea7b4244b3656ca33b19a950f092b5bbc718b40c`,
	},
	{
		// Fixes `BUG: KASAN: slab-use-after-free in binder_add_device` at boot.
		// Title: binderfs: fix use-after-free in binder_devices
		GuiltyHash: `12d909cac1e1c4147cc3417fee804ee12fc6b984`,
		FixHash:    `e77aff5528a183462714f750e45add6cc71e276a`,
	},
	{
		// Fixes `unregister_netdevice: waiting for batadv0 to become free. Usage count = 3`.
		// Several v6.15-rc* tags are essentially unfuzzeable because of this.
		// Title: batman-adv: Fix double-hold of meshif when getting enabled
		GuiltyHash: `00b35530811f2aa3d7ceec2dbada80861c7632a8`,
		FixHash:    `10a77965760c6e2b3eef483be33ae407004df894`,
	},
	{
		// Fixes `ld.lld: error: undefined symbol: devm_drm_of_get_bridge`.
		// Title: drm/bridge: select DRM_KMS_HELPER for AUX_BRIDGE
		GuiltyHash: `2a04739139b2b2761571e18937e2400e71eff664`,
		FixHash:    `b12fa5e76e1463fc5a196f2717040e4564e184b6`,
	},
	{
		// Fixes `undefined symbol: devm_drm_of_get_bridge referenced by nb7vpq904m.c`.
		// Title: usb: typec: nb7vpq904m: switch to DRM_AUX_BRIDGE
		GuiltyHash: `2a04739139b2b2761571e18937e2400e71eff664`,
		FixHash:    `c5d296bad640b190c52ef7508114d70e971a4bba`,
	},
}
