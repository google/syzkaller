// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"math/rand"
	"sort"
	"testing"

	"github.com/google/syzkaller/pkg/image"
	"github.com/google/syzkaller/pkg/testutil"
)

func TestGenericHeatmap(t *testing.T) {
	t.Parallel()
	// A test case is some data with the regions the heatmap is permitted to choose.
	testData := []struct {
		data    []byte
		regions []region
	}{
		{
			// Normal usage test.
			[]byte(
				"4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh" +
					"4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh" +
					"4eHh4eHh4eHh4eHh4Q5GTbHh4eHh4eHh4eHh4eHhcOHh4eHh4eHh4eHh4eHh4eHh4eHh4eEfNuHh4XPh" +
					"4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHjd+GRzcLh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh" +
					"4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4dpiSwpoReHh4eHh4eHh4eHh4eHh4eHh4eHh" +
					"4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4bGfM+Hh4eHh4eHh4eHh4eHh4eHh4eHh4eHh" +
					"4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh" +
					"4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh" +
					"4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh" +
					"mpNKOZnS4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh4eHh" +
					"4eHh4eHh4eHh4eHh4eHh4Q=="),
			[]region{{128, 384}, {512, 576}},
		},
		{
			// Test all constant bytes, i.e. falling back to uniform selection.
			[]byte(
				"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
					"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
					"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
					"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
					"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" +
					"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
			[]region{{0, 324}}, // Anywhere in the data.
		},
	}

	const tries = 10
	iters := testutil.IterCount() / tries

	r := rand.New(testutil.RandSource(t))
	for _, test := range testData {
		data, err := image.DecodeB64(test.data)
		if err != nil {
			t.Fatalf("bad decode: %v", err)
		}
		for i := 0; i < iters; i++ {
			hm := MakeGenericHeatmap(data, r).(*GenericHeatmap)

			for j := 0; j < tries; j++ {
				index := hm.ChooseLocation()
				if !checkIndex(index, len(data), test.regions) {
					hm.debugPrint(t, data, test.regions)
					t.Fatalf("selected index %d does not fall in a region", index)
				}
			}
		}
	}
}

// Check an index is within some regions.
func checkIndex(index, maxIndex int, regions []region) bool {
	if index < 0 || index >= maxIndex {
		return false
	}

	for _, region := range regions {
		if region.start <= index && index < region.end {
			return true
		}
	}
	return false
}

type region struct {
	start int
	end   int
}

func (hm *GenericHeatmap) debugPrint(t *testing.T, data []byte, regions []region) {
	// Print data.
	t.Logf("data: len = %d", len(data))
	for j := 0; j < len(data); j += granularity {
		end := min(j+granularity, len(data))
		t.Logf("%8d: %x", j*granularity, data[j:end])
	}
	t.Log("\n")

	// Print selected regions in data.
	sort.Slice(regions, func(i, j int) bool {
		return regions[i].start < regions[j].start
	})
	for j, region := range regions {
		t.Logf("region  %4d: %8v - %8v", j, region.start, region.end)
	}
	t.Log("\n")

	// Print heatmap.
	t.Logf("generic heatmap (total segment length %d)", hm.length)
	for j, seg := range hm.segments {
		t.Logf("segment %4d: %8v - %8v", j, seg.offset, seg.offset+seg.length)
	}
	t.Log("\n\n\n")
}
