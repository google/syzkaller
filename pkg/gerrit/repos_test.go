// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package gerrit

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestProjectForRepo(t *testing.T) {
	{
		got, err := projectForRepo("git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git")
		require.NoError(t, err)
		require.Equal(t, "linux/kernel/git/torvalds/linux", got)
	}
	{
		got, err := projectForRepo("https://git.kernel.org/pub/scm/linux/kernel/git/bpf/bpf-next.git")
		require.NoError(t, err)
		require.Equal(t, "linux/kernel/git/bpf/bpf-next", got)
	}
	{
		got, err := projectForRepo("https://kernel.googlesource.com/pub/scm/linux/kernel/git/davem/net.git")
		require.NoError(t, err)
		require.Equal(t, "linux/kernel/git/davem/net", got)
	}
	{
		// Valid repo, but we don't mirror it.
		_, err := projectForRepo("git://git.kernel.org/pub/scm/linux/kernel/git/ast/bpf.git")
		require.Error(t, err)
	}
}
