// Copyright 2023 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package minimize

import (
	"errors"
	"fmt"
	"math"
	"strings"
)

type Config[T any] struct {
	// The original slice is minimized with respect to this predicate.
	// If Pred(X) returns true, X is assumed to contain all elements that must stay.
	Pred func([]T) (bool, error)
	// MaxSteps is a limit on the number of predicate calls during bisection.
	// If it's hit, the bisection continues as if Pred() begins to return false.
	// If it's set to 0 (by default), no limit is applied.
	MaxSteps int
	// MaxChunks sets a limit on the number of chunks pursued by the bisection algorithm.
	// If we hit the limit, bisection is stopped and Array() returns ErrTooManyChunks
	// anongside the intermediate bisection result (a valid, but not fully minimized slice).
	MaxChunks int
	// Logf is used for sharing debugging output.
	Logf func(string, ...interface{})
}

// Slice() finds a minimal subsequence of slice elements that still gives Pred() == true.
// The algorithm works by sequentially splitting the slice into smaller-size chunks and running
// Pred() witout those chunks. Slice() receives the original slice chunks.
// The expected number of Pred() runs is O(|result|*log2(|elements|)).
func Slice[T any](config Config[T], slice []T) ([]T, error) {
	if config.Logf == nil {
		config.Logf = func(string, ...interface{}) {}
	}
	ctx := &sliceCtx[T]{
		Config: config,
		chunks: []*arrayChunk[T]{
			{
				elements: slice,
			},
		},
	}
	return ctx.bisect()
}

type sliceCtx[T any] struct {
	Config[T]
	chunks   []*arrayChunk[T]
	predRuns int
}

type arrayChunk[T any] struct {
	elements []T
	final    bool // There's no way to further split this chunk.
}

// ErrTooManyChunks is returned if the number of necessary chunks surpassed MaxChunks.
var ErrTooManyChunks = errors.New("the bisection process is following too many necessary chunks")

func (ctx *sliceCtx[T]) bisect() ([]T, error) {
	// At first, we don't know if the original chunks are really necessary.
	err := ctx.splitChunks(false)
	// Then, keep on splitting the chunks layer by layer until we have identified
	// all necessary elements.
	// This way we ensure that we always go from larger to smaller chunks.
	for err == nil && !ctx.done() {
		if ctx.MaxChunks > 0 && len(ctx.chunks) > ctx.MaxChunks {
			err = ErrTooManyChunks
			break
		}
		err = ctx.splitChunks(true)
	}
	if err != nil && err != ErrTooManyChunks {
		return nil, err
	}
	return ctx.elements(), err
}

// splitChunks() splits each chunk in two and only leaves the necessary sub-parts.
func (ctx *sliceCtx[T]) splitChunks(someNeeded bool) error {
	ctx.Logf("split chunks (needed=%v): %s", someNeeded, ctx.chunkInfo())
	splitInto := 2
	if !someNeeded && len(ctx.chunks) == 1 {
		// It's our first iteration.
		splitInto = ctx.initialSplit(len(ctx.chunks[0].elements))
	}
	var newChunks []*arrayChunk[T]
	for i, chunk := range ctx.chunks {
		if chunk.final {
			newChunks = append(newChunks, chunk)
			continue
		}
		ctx.Logf("split chunk #%d of len %d into %d parts", i, len(chunk.elements), splitInto)
		chunks := splitChunk[T](chunk.elements, splitInto)
		if len(chunks) == 1 && someNeeded {
			ctx.Logf("no way to further split the chunk")
			chunk.final = true
			newChunks = append(newChunks, chunk)
			continue
		}
		foundNeeded := false
		for j := range chunks {
			ctx.Logf("testing without sub-chunk %d/%d", j+1, len(chunks))
			if j < len(chunks)-1 || foundNeeded || !someNeeded {
				ret, err := ctx.predRun(
					newChunks,
					mergeRawChunks(chunks[j+1:]),
					ctx.chunks[i+1:],
				)
				if err != nil {
					return err
				}
				if ret {
					ctx.Logf("the chunk can be dropped")
					continue
				}
			} else {
				ctx.Logf("no need to test this chunk, it's definitely needed")
			}
			foundNeeded = true
			newChunks = append(newChunks, &arrayChunk[T]{
				elements: chunks[j],
			})
		}
	}
	ctx.chunks = newChunks
	return nil
}

// Since Pred() runs can be costly, the objective is to get the most out of the
// limited number of Pred() calls.
// We try to achieve it by splitting the initial array in more than 2 elements.
func (ctx *sliceCtx[T]) initialSplit(size int) int {
	// If the number of steps is small and the number of elements is big,
	// let's just split the initial array into MaxSteps chunks.
	// There's no solid reasoning behind the condition below, so feel free to
	// change it if you have better ideas.
	if ctx.MaxSteps > 0 && math.Log2(float64(size)) > float64(ctx.MaxSteps) {
		return ctx.MaxSteps
	}
	// Otherwise let's split in 3.
	return 3
}

// predRun() determines whether (before + mid + after) covers the necessary elements.
func (ctx *sliceCtx[T]) predRun(before []*arrayChunk[T], mid []T, after []*arrayChunk[T]) (bool, error) {
	if ctx.MaxSteps > 0 && ctx.predRuns >= ctx.MaxSteps {
		ctx.Logf("we have reached the limit on predicate runs (%d); pretend it returns false",
			ctx.MaxSteps)
		return false, nil
	}
	ctx.predRuns++
	return ctx.Pred(mergeChunks(before, mid, after))
}

// The bisection process is done once every chunk is marked as final.
func (ctx *sliceCtx[T]) done() bool {
	if ctx.MaxSteps > 0 && ctx.predRuns >= ctx.MaxSteps {
		// No reason to continue.
		return true
	}
	for _, chunk := range ctx.chunks {
		if !chunk.final {
			return false
		}
	}
	return true
}

func (ctx *sliceCtx[T]) elements() []T {
	return mergeChunks(ctx.chunks, nil, nil)
}

func (ctx *sliceCtx[T]) chunkInfo() string {
	var parts []string
	for _, chunk := range ctx.chunks {
		str := ""
		if chunk.final {
			str = ", final"
		}
		parts = append(parts, fmt.Sprintf("<%d%s>", len(chunk.elements), str))
	}
	return strings.Join(parts, ", ")
}

func mergeChunks[T any](before []*arrayChunk[T], mid []T, after []*arrayChunk[T]) []T {
	var ret []T
	for _, chunk := range before {
		ret = append(ret, chunk.elements...)
	}
	ret = append(ret, mid...)
	for _, chunk := range after {
		ret = append(ret, chunk.elements...)
	}
	return ret
}

func mergeRawChunks[T any](chunks [][]T) []T {
	var ret []T
	for _, chunk := range chunks {
		ret = append(ret, chunk...)
	}
	return ret
}

func splitChunk[T any](chunk []T, parts int) [][]T {
	chunkSize := (len(chunk) + parts - 1) / parts
	if chunkSize == 0 {
		chunkSize = 1
	}
	var ret [][]T
	for i := 0; i < len(chunk); i += chunkSize {
		end := i + chunkSize
		if end > len(chunk) {
			end = len(chunk)
		}
		ret = append(ret, chunk[i:end])
	}
	return ret
}
