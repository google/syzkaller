// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseManifest(t *testing.T) {
	info, err := ParseManifest("http://localhost", []byte(testManifest))
	assert.NoError(t, err)
	assert.Len(t, info, 2)
	assert.Equal(t, 1, info["name"].Epochs)
	second := info["name2"]
	assert.Equal(t, 2, second.Epochs)
	assert.Equal(t, "http://localhost/name2/git/1.git", second.EpochURL(1))
}

const testManifest = `{
  "/name2/git/1.git": {
    "modified": 1638806983,
    "owner": null,
    "reference": null,
    "description": "Another repo",
    "fingerprint": "788f666601f9641375e11e167b5e6b1eeb549cbb"
  },
  "/name/git/0.git": {
    "modified": 1638806983,
    "owner": null,
    "reference": null,
    "description": "Some repo",
    "fingerprint": "788f666601f9641375e11e167b5e6b1eeb549cbb"
  },
  "/name2/git/0.git": {
    "modified": 1638806983,
    "owner": null,
    "reference": null,
    "description": "Another repo",
    "fingerprint": "788f666601f9641375e11e167b5e6b1eeb549cbb"
  }
}`
