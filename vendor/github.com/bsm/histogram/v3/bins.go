package histogram

import "math"

type bin struct {
	w float64 // weight
	v float64 // value
}

func (b bin) Sum() float64 { return math.Abs(b.w) * b.v }

// ----------------------------------------------------------

type binSlice []bin

func (s binSlice) Len() int           { return len(s) }
func (s binSlice) Less(i, j int) bool { return s[i].v < s[j].v }
func (s binSlice) Swap(i, j int)      { s[i], s[j] = s[j], s[i] }
