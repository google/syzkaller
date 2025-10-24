
package stat

import (
	"sync"
	"time"
)

type AverageParameter interface {
	time.Duration
}

type AverageValue[T AverageParameter] struct {
	mu    sync.Mutex
	total int64
	avg   T
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
