package histogram

import (
	"math"
	"sort"
)

// Histogram is a probabilistic, fixed-size data structure, able to
// accommodate massive data streams while predicting distributions
// and quantiles much more accurately than a sample-based approach.
//
// Please note that a historgram is not thread-safe. All operations
// must be protected by a mutex if used across multiple goroutines.
type Histogram struct {
	bins   []bin
	size   int
	weight float64

	min, max float64
}

// New creates a new histogram with a maximum size.
func New(sz int) *Histogram {
	h := new(Histogram)
	h.Reset(sz)
	return h
}

// Reset resets the struct to its initial state with
// a specific size.
func (h *Histogram) Reset(sz int) {
	if sz < cap(h.bins) {
		h.bins = h.bins[:0]
	} else {
		h.bins = make([]bin, 0, sz+1)
	}

	h.size = sz
	h.min = math.NaN()
	h.max = math.NaN()
	h.weight = 0
}

// Copy copies h to x and returns x. If x is passed as nil
// a new Histogram will be inited.
func (h *Histogram) Copy(x *Histogram) *Histogram {
	if x == nil {
		x = new(Histogram)
	}
	if sz := h.size; sz < cap(x.bins) {
		x.bins = x.bins[:len(h.bins)]
	} else {
		x.bins = make([]bin, len(h.bins), sz+1)
	}
	copy(x.bins, h.bins)

	x.size = h.size
	x.min = h.min
	x.max = h.max
	x.weight = h.weight
	return x
}

// Count returns the observed weight truncated to the next integer.
func (h *Histogram) Count() int { return int(h.weight) }

// Weight returns the observed weight (usually, the number of items seen).
func (h *Histogram) Weight() float64 { return h.weight }

// Min returns the smallest observed value.
// Returns NaN if Count is zero.
func (h *Histogram) Min() float64 {
	if h.weight == 0 {
		return math.NaN()
	}
	return h.min
}

// Max returns the largest observed value.
// Returns NaN if Count is zero.
func (h *Histogram) Max() float64 {
	if h.weight == 0 {
		return math.NaN()
	}
	return h.max
}

// Sum returns the (approximate) sum of all observed values.
// Returns NaN if Count is zero.
func (h *Histogram) Sum() float64 {
	if h.weight == 0 {
		return math.NaN()
	}

	var sum float64
	for _, b := range h.bins {
		sum += b.Sum()
	}
	return sum
}

// Mean returns the (approximate) average observed value.
// Returns NaN if Count is zero.
func (h *Histogram) Mean() float64 {
	if h.weight == 0 {
		return math.NaN()
	}
	return h.Sum() / h.weight
}

// Variance returns the (approximate) sample variance of the distribution.
// Returns NaN if Count is zero.
func (h *Histogram) Variance() float64 {
	if h.weight <= 1 {
		return math.NaN()
	}

	var vv float64
	mean := h.Mean()
	for _, b := range h.bins {
		delta := mean - b.v
		vv += delta * delta * b.w
	}
	return vv / (h.weight - 1)
}

// Quantile returns the (approximate) quantile of the distribution.
// Accepted values for q are between 0.0 and 1.0.
// Returns NaN if Count is zero or bad inputs.
func (h *Histogram) Quantile(q float64) float64 {
	if h.weight == 0 || q < 0.0 || q > 1.0 {
		return math.NaN()
	} else if q == 0.0 {
		return h.min
	} else if q == 1.0 {
		return h.max
	}

	delta := q * h.weight
	pos := 0
	for w0 := 0.0; pos < len(h.bins); pos++ {
		w1 := math.Abs(h.bins[pos].w) / 2.0
		if delta-w1-w0 < 0 {
			break
		}
		delta -= (w1 + w0)
		w0 = w1
	}

	switch pos {
	case 0: // lower bound
		return h.solve(bin{v: h.min, w: 0}, h.bins[pos], delta)
	case len(h.bins): // upper bound
		return h.solve(h.bins[pos-1], bin{v: h.max, w: 0}, delta)
	default:
		return h.solve(h.bins[pos-1], h.bins[pos], delta)
	}
}

// Add is the same as AddWeight(v, 1)
func (h *Histogram) Add(v float64) { h.AddWeight(v, 1) }

// AddN is the same as AddWeight(v, float64(n))
func (h *Histogram) AddN(v float64, n int) { h.AddWeight(v, float64(n)) }

// AddWeight adds observations of v with the weight w to the distribution.
func (h *Histogram) AddWeight(v, w float64) {
	if w <= 0 {
		return
	}
	if h.weight == 0 || v < h.min {
		h.min = v
	}
	if h.weight == 0 || v > h.max {
		h.max = v
	}

	h.insert(v, w)
	h.weight += w

	h.prune()
}

// Merge sets h to the union x ∪ y.
func (h *Histogram) Merge(x, y *Histogram) {
	h.bins = append(h.bins[:0], x.bins...)
	h.bins = append(h.bins, y.bins...)
	sort.Sort(binSlice(h.bins))
	h.prune()
}

// MergeWith sets h to the union h ∪ x.
func (h *Histogram) MergeWith(x *Histogram) { h.Merge(h, x) }

// NumBins returns bin (bucket) count.
func (h *Histogram) NumBins() int { return len(h.bins) }

// Bin returns bin (bucket) data.
// Requested index must be 0 <= i < NumBins() or it will panic.
func (h *Histogram) Bin(i int) (value, weight float64) {
	b := h.bins[i]
	return b.v, b.w
}

func (h *Histogram) solve(b1, b2 bin, delta float64) float64 {
	w1, w2 := b1.w, b2.w

	// return if both bins are exact (unmerged)
	if w1 > 0 && w2 > 0 {
		return b2.v
	}

	// normalise
	w1, w2 = math.Abs(w1), math.Abs(w2)

	// calculate multiplier
	var z float64
	if w1 == w2 {
		z = delta / w1
	} else {
		a := 2 * (w2 - w1)
		b := 2 * w1
		z = (math.Sqrt(b*b+4*a*delta) - b) / a
	}
	return b1.v + (b2.v-b1.v)*z
}

func (h *Histogram) insert(v, w float64) {
	pos := h.search(v)
	if pos < len(h.bins) && h.bins[pos].v == v {
		h.bins[pos].w += math.Copysign(w, h.bins[pos].w)
		return
	}

	maxi := len(h.bins)
	h.bins = h.bins[:len(h.bins)+1]
	if pos != maxi {
		copy(h.bins[pos+1:], h.bins[pos:])
	}
	h.bins[pos].w = w
	h.bins[pos].v = v
}

func (h *Histogram) prune() {
	for len(h.bins) > h.size {
		delta := math.MaxFloat64
		pos := 0
		for i := 0; i < len(h.bins)-1; i++ {
			b1, b2 := h.bins[i], h.bins[i+1]
			if x := b2.v - b1.v; x < delta {
				pos, delta = i, x
			}
		}

		b1, b2 := h.bins[pos], h.bins[pos+1]
		w := math.Abs(b1.w) + math.Abs(b2.w)
		v := (b1.Sum() + b2.Sum()) / w
		h.bins[pos+1].w = -w
		h.bins[pos+1].v = v
		h.bins = h.bins[:pos+copy(h.bins[pos:], h.bins[pos+1:])]
	}
}

func (h *Histogram) search(v float64) int {
	return sort.Search(len(h.bins), func(i int) bool { return h.bins[i].v >= v })
}
