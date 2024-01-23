// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package gce

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateZone(t *testing.T) {
	assert.True(t, validateZone("us-west1-b"))
	assert.True(t, validateZone("us-central1-a"))
	assert.False(t, validateZone("us-central1"))
}

func TestZoneToRegion(t *testing.T) {
	assert.Equal(t, "us-west1", zoneToRegion("us-west1-b"))
	assert.Equal(t, "northamerica-northeast2", zoneToRegion("northamerica-northeast2-a"))
}
