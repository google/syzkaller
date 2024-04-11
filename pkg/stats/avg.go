// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package stats

import (
	"sync"
	"time"
)

type AverageParameter interface {
	time.Duration | float64
}

type AverageValue[T AverageParameter] struct {
	mu    sync.Mutex
	total int64
	avg   T
}

func (av *AverageValue[T]) Count() int64 {
	av.mu.Lock()
	defer av.mu.Unlock()
	return av.total
}

func (av *AverageValue[T]) Value() T {
	av.mu.Lock()
	defer av.mu.Unlock()
	return av.avg
}

func (av *AverageValue[T]) Save(val T) {
	av.mu.Lock()
	defer av.mu.Unlock()
	av.total++
	av.avg += (val - av.avg) / T(av.total)
}
