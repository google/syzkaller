// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package diff

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNeedReproForTitle(t *testing.T) {
	for title, skip := range map[string]bool{
		"no output from test machine":                          false,
		"SYZFAIL: read failed":                                 false,
		"lost connection to test machine":                      false,
		"INFO: rcu detected stall in clone":                    false,
		"WARNING in arch_install_hw_breakpoint":                true,
		"KASAN: slab-out-of-bounds Write in __bpf_get_stackid": true,
	} {
		assert.Equal(t, skip, needReproForTitle(title), "title=%q", title)
	}
}
