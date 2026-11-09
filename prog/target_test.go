// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRequiredGlobs(t *testing.T) {
	assert.Equal(t, requiredGlobs("aa/bb"), []string{"aa/bb"})
	assert.Equal(t, requiredGlobs("aa:bb"), []string{"aa", "bb"})
	assert.Equal(t, requiredGlobs("aa:bb:-cc:dd"), []string{"aa", "bb", "dd"})
}

func TestPopulateGlob(t *testing.T) {
	allowAll := func(string) bool { return true }
	assert.Empty(t, populateGlob("aa", map[string][]string{
		"bb": {"c"},
	}, allowAll))
	assert.Equal(t, []string{"d", "e"}, populateGlob("aa", map[string][]string{
		"aa": {"d", "e"},
		"bb": {"c"},
	}, allowAll))
	assert.Equal(t, []string{"d", "e", "f"}, populateGlob("aa:cc", map[string][]string{
		"aa": {"d", "e"},
		"bb": {"c"},
		"cc": {"f", "d"},
	}, allowAll))
	assert.Equal(t, []string{"d", "f"}, populateGlob("aa:cc:-e", map[string][]string{
		"aa": {"d", "e"},
		"bb": {"c"},
		"cc": {"f", "d"},
	}, allowAll))
	assert.Equal(t, []string{"d"}, populateGlob("aa:cc", map[string][]string{
		"aa": {"d", "e"},
		"cc": {"f", "d"},
	}, func(path string) bool {
		return path == "d"
	}))
	assert.Equal(t, []string{"d"}, populateGlob("aa:cc:-f", map[string][]string{
		"aa": {"d", "e"},
		"cc": {"f", "d"},
	}, func(path string) bool {
		return path != "e"
	}))
}

func TestUpdateGlobsAllowFilePath(t *testing.T) {
	globBuf := &BufferType{
		Kind:    BufferGlob,
		SubKind: "/sys/**/*",
	}
	target := &Target{
		Syscalls: []*Syscall{
			{
				Name: "openat$test",
				Args: []Field{{Name: "dir", Type: globBuf}},
			},
		},
		AllowFilePath: func(path string) bool {
			return path != "/sys/bus/pci/drivers_probe"
		},
	}
	target.UpdateGlobs(map[string][]string{
		"/sys/**/*": {"/sys/bus/pci/drivers_probe", "/sys/bus/pci/rescan"},
	})
	assert.Equal(t, []string{"/sys/bus/pci/rescan"}, globBuf.Values)

	target.UpdateGlobs(map[string][]string{
		"/sys/**/*": {"/sys/bus/pci/drivers_probe"},
	})
	assert.Empty(t, globBuf.Values)
}
