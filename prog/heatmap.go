// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"fmt"
	"math/rand"
)

// Our heatmaps are a flexible mechanism to assign a probability distribution to
// some collection of bytes. Usage:
//  1. Choose a heatmap and initialize it: `hm := MakeXYZHeatmap(data)`.
//     Different heatmaps implement different probability distributions
//     (for now there is only one).
//  2. Select random indices according to the probability distribution:
//     `idx := hm.ChooseLocation(r)`.
type Heatmap interface {
	NumMutations() int
	ChooseLocation() int
}

// Generic heatmaps model a probability distribution based on sparse data,
// prioritising selection of regions which are not a single repeated byte. It
// views data as a series of chunks of length `granularity`, ignoring chunks
// which are a single repeated byte. Indices are chosen uniformly amongst the
// remaining "interesting" segments.
func MakeGenericHeatmap(data []byte, r *rand.Rand) Heatmap {
	if len(data) == 0 {
		panic("cannot create a GenericHeatmap with no data")
	}
	hm := &GenericHeatmap{
		r: r,
	}
	hm.length, hm.segments = calculateLengthAndSegments(data, granularity)
	return hm
}

func (hm *GenericHeatmap) NumMutations() int {
	// At least one mutation.
	n := 1
	// + up to about one mutation every 4 KB of heatmap size.
	n += hm.r.Intn(hm.length/(4<<10) + 1)
	// + up to 4 mutations at random so that even small images can get more than one.
	n += hm.r.Intn(5)
	// But don't do too many as it will most likely corrupt the image.
	if max := 10; n > max {
		n = max
	}
	return n
}

func (hm *GenericHeatmap) ChooseLocation() int {
	// Uniformly choose an index within one of the segments.
	heatmapIdx := hm.r.Intn(hm.length)
	rawIdx := translateIdx(heatmapIdx, hm.segments)
	return rawIdx
}

type GenericHeatmap struct {
	r        *rand.Rand
	segments []segment // "Interesting" parts of the data.
	length   int       // Sum of all segment lengths.
}

type segment struct {
	offset int
	length int
}

const granularity = 64 // Chunk size in bytes for processing the data.

// Determine the "interesting" segments of data, also returning their combined length.
func calculateLengthAndSegments(data []byte, granularity int) (int, []segment) {
	// Offset and length of current segment, total length of all segments, length of original data.
	offset, currentLength, totalLength, rawLength := 0, 0, 0, len(data)
	segments := []segment{}

	// Save a segment.
	saveSegment := func() {
		if currentLength != 0 {
			segments = append(segments, segment{offset: offset, length: currentLength})
			offset, totalLength, currentLength = offset+currentLength, totalLength+currentLength, 0
		}
	}

	for len(data) > 0 {
		var chunk []byte
		if len(data) < granularity {
			chunk, data = data, nil
		} else {
			chunk, data = data[:granularity], data[granularity:]
		}

		// Check if buffer contains only a single value.
		byt0, isConstant := chunk[0], true
		for _, byt := range chunk {
			if byt != byt0 {
				isConstant = false
				break
			}
		}

		if !isConstant {
			// Non-constant - extend the current segment.
			currentLength += len(chunk)
		} else {
			// Save current segment.
			saveSegment()
			// Skip past the constant bytes.
			offset += len(chunk)
		}
	}

	// Save final segment.
	saveSegment()

	if len(segments) == 0 {
		// We found no segments, i.e. the data is all "boring". Fall back to a
		// uniform probability distribution over the original data by considering it
		// as one long segment.
		return rawLength, append(segments, segment{offset: 0, length: rawLength})
	}

	return totalLength, segments
}

// Convert from an index into "interesting" segments to an index into raw data.
// I.e. view `idx` as an index into the concatenated segments, and translate
// this to an index into the original underlying data. E.g.:
//
//	segs = []segment{{offset: 10, length: 20}, {offset: 50, length: 10}}
//	translateIdx(25, segs) = 5
//
// I.e. we index element 5 of the second segment, so element 55 of the raw data.
func translateIdx(idx int, segs []segment) int {
	if idx < 0 {
		panic(fmt.Sprintf("translateIdx: negative index %v", idx))
	}
	savedIdx := idx
	for _, seg := range segs {
		if idx < seg.length {
			return seg.offset + idx
		}
		idx -= seg.length
	}
	panic(fmt.Sprintf("translateIdx: index out of range %v", savedIdx))
}
