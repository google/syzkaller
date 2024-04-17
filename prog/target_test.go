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
	assert.Empty(t, populateGlob("aa", map[string][]string{
		"bb": {"c"},
	}))
	assert.Equal(t, populateGlob("aa", map[string][]string{
		"aa": {"d", "e"},
		"bb": {"c"},
	}), []string{"d", "e"})
	assert.Equal(t, populateGlob("aa:cc", map[string][]string{
		"aa": {"d", "e"},
		"bb": {"c"},
		"cc": {"f", "d"},
	}), []string{"d", "e", "f"})
	assert.Equal(t, populateGlob("aa:cc:-e", map[string][]string{
		"aa": {"d", "e"},
		"bb": {"c"},
		"cc": {"f", "d"},
	}), []string{"d", "f"})
}
