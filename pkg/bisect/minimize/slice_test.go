// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package minimize

import (
	"fmt"
	"math"
	"math/rand"
	"testing"
	"time"

	"github.com/google/syzkaller/pkg/testutil"
	"github.com/stretchr/testify/assert"
)

func TestBisectSliceToZero(t *testing.T) {
	t.Parallel()
	array := make([]int, 100)
	ret, err := Slice(Config[int]{
		Pred: func(arr []int) (bool, error) {
			// No elements are needed.
			return true, nil
		},
		Logf: t.Logf,
	}, array)
	assert.NoError(t, err)
	assert.Len(t, ret, 0)
}

func TestBisectSliceFull(t *testing.T) {
	t.Parallel()
	array := make([]int, 100)
	ret, err := Slice(Config[int]{
		Pred: func(arr []int) (bool, error) {
			// All elements are needed.
			return false, nil
		},
		Logf: t.Logf,
	}, array)
	assert.NoError(t, err)
	assert.Equal(t, ret, array)
}

func TestBisectRandomSlice(t *testing.T) {
	t.Parallel()
	r := rand.New(testutil.RandSource(t))
	for i := 0; i < testutil.IterCount(); i++ {
		// Create an array of random size and set the elements that must remain to non-zero values.
		size := r.Intn(50)
		subset := r.Intn(size + 1)
		array := make([]int, size)
		for _, j := range r.Perm(size)[:subset] {
			array[j] = j + 1
		}
		var expect []int
		for _, j := range array {
			if j > 0 {
				expect = append(expect, j)
			}
		}
		predCalls := 0
		ret, err := Slice(Config[int]{
			Pred: func(arr []int) (bool, error) {
				predCalls++
				// All elements of the subarray must be present.
				nonZero := 0
				for _, x := range arr {
					if x > 0 {
						nonZero++
					}
				}
				return nonZero == subset, nil
			},
			Logf: t.Logf,
		}, array)
		assert.NoError(t, err)
		assert.EqualValues(t, expect, ret)
		// Ensure we don't make too many predicate calls.
		maxCalls := 3 + 2*subset*(1+int(math.Floor(math.Log2(float64(size)))))
		assert.LessOrEqual(t, predCalls, maxCalls)
	}
}

func BenchmarkSplits(b *testing.B) {
	for _, guilty := range []int{1, 2, 3, 4} {
		guilty := guilty
		b.Run(fmt.Sprintf("%d_guilty", guilty), func(b *testing.B) {
			var sum int
			for i := 0; i < b.N; i++ {
				sum += runMinimize(guilty)
			}
			b.ReportMetric(float64(sum)/float64(b.N), "remaining-elements")
		})
	}
}

func runMinimize(guilty int) int {
	const size = 300
	const steps = 5

	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	array := make([]int, size)
	for _, j := range r.Perm(size)[:guilty] {
		array[j] = 1
	}

	ret, _ := Slice(Config[int]{
		MaxSteps: steps,
		Pred: func(arr []int) (bool, error) {
			nonZero := 0
			for _, x := range arr {
				if x > 0 {
					nonZero++
				}
			}
			return nonZero == guilty, nil
		},
	}, array)
	return len(ret)
}
