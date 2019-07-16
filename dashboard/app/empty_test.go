// Copyright 2019 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package dash

import (
	"testing"
)

// blaze+tricoder fail when all test files are excluded by tags.
// Work around the bug by adding an empty test file.
func TestEmpty(t *testing.T) {
}
