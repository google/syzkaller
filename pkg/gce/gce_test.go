// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package gce

import (
	"fmt"
	"net/http"
	"net/http/httptest"
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

func TestDiskSizeGB(t *testing.T) {
	assert.Equal(t, 10, diskSizeGB("c4a-standard-2"))
	assert.Equal(t, 0, diskSizeGB("e2-standard-2"))
}

func TestLocalZone(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, "/instance/zone", r.URL.Path)
		fmt.Fprint(w, "projects/12341234/zones/us-central1-c")
	}))
	defer ts.Close()

	ctx := &Context{
		metadataServer: ts.URL + "/",
	}
	zone, err := ctx.localZone()
	assert.NoError(t, err)
	assert.Equal(t, "us-central1-c", zone)
}

func TestZoneListPrioritization(t *testing.T) {
	zl := &zoneList{
		preferredZone: "zone-b",
		list:          []string{"zone-a", "zone-b", "zone-c", "zone-d"},
		score: map[string]float64{
			"zone-a": 1.0,
			"zone-b": 1.0,
			"zone-c": 1.0,
			"zone-d": 1.0,
		},
	}

	// Initial order should prioritize zone-b.
	zl.sort()
	assert.Equal(t, []string{"zone-b", "zone-a", "zone-c", "zone-d"}, zl.list)

	// zone-b gets an insertion, score = 1.0 * 0.9 + 0.1 = 1.0
	// Order should stay the same.
	zl.recordInsertionSuccess("zone-b")
	assert.Equal(t, []string{"zone-b", "zone-a", "zone-c", "zone-d"}, zl.list)

	// zone-b gets a preemption, score = 1.0 * 0.9 + 0.08 = 0.98
	// Order should now put zone-b at the end since its score is lowest.
	zl.recordPreemption("zone-b")
	assert.Equal(t, []string{"zone-a", "zone-c", "zone-d", "zone-b"}, zl.list)

	// zone-a gets an insertion failure, score = 1.0 * 0.9 = 0.9
	// Order should put zone-a at the very end.
	zl.recordInsertionFailure("zone-a")
	assert.Equal(t, []string{"zone-c", "zone-d", "zone-b", "zone-a"}, zl.list)

	// zone-c, and zone-d get preemptions, score = 1.0 * 0.9 + 0.08 = 0.98. But zone-c gets this preemption first, so it
	// should be after zone-d. zone-b is our preferred zone, and its score is also 0.98. It should be back at the top.
	zl.recordPreemption("zone-c")
	zl.recordPreemption("zone-d")
	assert.Equal(t, []string{"zone-b", "zone-d", "zone-c", "zone-a"}, zl.list)

	// zone-d gets 10 insertions. Score will approach 1.0.
	for range 10 {
		zl.recordInsertionSuccess("zone-d")
	}
	assert.Equal(t, []string{"zone-d", "zone-b", "zone-c", "zone-a"}, zl.list)
}
