// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sample

import (
	"reflect"
	"testing"
)

func TestMedian(t *testing.T) {
	tests := []struct {
		input     []float64
		minMedian float64
		maxMedian float64
	}{
		{
			input:     []float64{1, 2, 3},
			minMedian: 1.99, // we cannot do exact floating point equality comparison
			maxMedian: 2.01,
		},
		{
			input:     []float64{0, 1, 2, 3},
			minMedian: 1.0,
			maxMedian: 2.0,
		},
	}
	for _, test := range tests {
		sample := Sample{Xs: test.input}
		median := sample.Median()
		if median < test.minMedian || median > test.maxMedian {
			t.Errorf("sample %v, median got %v, median expected [%v;%v]",
				test.input, median, test.minMedian, test.maxMedian)
		}
	}
}

func TestRemoveOutliers(t *testing.T) {
	// Some tests just to check the overall sanity of the method.
	tests := []struct {
		input  []float64
		output []float64
	}{
		{
			input:  []float64{-20, 1, 2, 3, 4, 5},
			output: []float64{1, 2, 3, 4, 5},
		},
		{
			input:  []float64{1, 2, 3, 4, 25},
			output: []float64{1, 2, 3, 4},
		},
		{
			input:  []float64{-10, -5, 0, 5, 10, 15},
			output: []float64{-10, -5, 0, 5, 10, 15},
		},
	}
	for _, test := range tests {
		sample := Sample{Xs: test.input}
		result := sample.RemoveOutliers()
		result.Sort()
		if !reflect.DeepEqual(result.Xs, test.output) {
			t.Errorf("input: %v, expected no outliers: %v, got: %v",
				test.input, test.output, result.Xs)
		}
	}
}
