// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package vcs

// BackportCommit describes a fix commit that must be cherry-picked to an older
// kernel revision in order to enable kernel build / boot.
type BackportCommit struct {
	// If non-empty, it will be first ensured that this commit is reachable.
	GuiltyTitle string `json:"guilty_title"`
	// The hash of the commit to cherry-pick.
	FixHash string `json:"fix_hash"`
	// The title of the commit to cherry-pick.
	// It's used to determine whether the fix is already in place.
	FixTitle string `json:"fix_title"`
}

// linuxFixBackports() cherry-picks the commits necessary to compile/run older Linux kernel releases.
func linuxFixBackports(repo *git, extraCommits ...BackportCommit) error {
	list := append([]BackportCommit{}, pickLinuxCommits...)
	for _, info := range append(list, extraCommits...) {
		if info.GuiltyTitle != "" {
			guiltyCommit, err := repo.GetCommitByTitle(info.GuiltyTitle)
			if err != nil {
				return err
			}
			if guiltyCommit == nil {
				// The problem is not yet introduced.
				continue
			}
		}
		fixCommit, err := repo.GetCommitByTitle(info.FixTitle)
		if err != nil {
			return err
		}
		if fixCommit != nil {
			// The fix is already present.
			continue
		}
		_, err = repo.git("cherry-pick", "--no-commit", info.FixHash)
		if err != nil {
			return err
		}
	}
	return nil
}

var pickLinuxCommits = []BackportCommit{
	{
		// Compiling v4.6..v5.11 with a modern objtool, w/o this patch, results in the
		// following issue, when compiling with clang:
		// arch/x86/entry/thunk_64.o: warning: objtool: missing symbol table
		// We don't bisect that far back with neither clang nor gcc, so this should be fine:
		FixHash:  `1d489151e9f9d1647110277ff77282fe4d96d09b`,
		FixTitle: `objtool: Don't fail on missing symbol table`,
	},
	{
		// In newer compiler versions, kernel compilation fails with:
		// subcmd-util.h:56:23: error: pointer may be used after ‘realloc’ [-Werror=use-after-free]
		// 56 |                 ret = realloc(ptr, size);
		GuiltyTitle: `perf tools: Finalize subcmd independence`,
		FixHash:     `52a9dab6d892763b2a8334a568bd4e2c1a6fde66`,
		FixTitle:    `libsubcmd: Fix use-after-free for realloc(..., 0)`,
	},
	{
		// A number of old releases fail with KASAN: use-after-free in task_active_pid_ns.
		// The problem was actually present so long ago that we do not need to check whether
		// the guilty commit is present. We don't bisect that back (v2.*) anyway.
		FixHash:  `0711f0d7050b9e07c44bc159bbc64ac0a1022c7f`,
		FixTitle: "pid: take a reference when initializing `cad_pid`",
	},
}
