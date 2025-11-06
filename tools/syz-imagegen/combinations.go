// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import "sort"

// CoveringArray returns an array of representative parameter value combinations.
// The method considers parameters from the first to the last and first tries to
// generate all possible combinations of their values.
// If N != 0, the method eventually switches to ensuring that all value pairs
// are represented, once all pairs are covered - all triples (aka Covering Array).
func CoveringArray(params [][]string, n int) [][]string {
	var ret [][]int
	for paramID, param := range params {
		if len(ret) == 0 {
			ret = append(ret, []int{})
		}
		// If we can explore all combinations, do it.
		if len(ret)*len(param) <= n || n == 0 {
			var newRet [][]int
			for value := range param {
				for _, row := range ret {
					newRet = append(newRet, extendRow(row, value))
				}
			}
			ret = newRet
			continue
		}
		cover := &pairCoverage{cover: map[pairCombo]struct{}{}}

		// First, select a value for each row.
		var newRet [][]int
		for _, row := range ret {
			bestValue, bestCount := 0, coverDelta{}
			for valueID := range param {
				newCount := cover.wouldCover(row, paramID, valueID)
				if newCount.betterThan(bestCount) {
					bestValue = valueID
					bestCount = newCount
				}
			}
			newRet = append(newRet, extendRow(row, bestValue))
			cover.record(row, paramID, bestValue)
		}

		// Now that all previous combinations are preserved, we can (as long as
		// we don't exceed N) duplicate some of the rows to cover more.
		for len(newRet) < n {
			var bestRow []int
			bestValue, bestCount := 0, coverDelta{}
			for _, row := range ret {
				for valueID := range param {
					newCount := cover.wouldCover(row, paramID, valueID)
					if newCount.betterThan(bestCount) {
						bestRow = row
						bestValue = valueID
						bestCount = newCount
					}
				}
			}
			if !bestCount.betterThan(coverDelta{}) {
				break
			}
			newRet = append(newRet, extendRow(bestRow, bestValue))
			cover.record(bestRow, paramID, bestValue)
		}
		ret = newRet
	}
	sort.Slice(ret, func(i, j int) bool {
		rowA, rowB := ret[i], ret[j]
		for k := 0; k < len(rowA); k++ {
			if rowA[k] != rowB[k] {
				return rowA[k] < rowB[k]
			}
		}
		return false
	})
	var retStrings [][]string
	for _, row := range ret {
		var stringRow []string
		for paramID, valueID := range row {
			stringRow = append(stringRow, params[paramID][valueID])
		}
		retStrings = append(retStrings, stringRow)
	}
	return retStrings
}

type pairCoverage struct {
	cover map[pairCombo]struct{}
}

type coverDelta struct {
	pairs   int
	triples int
}

func (c coverDelta) betterThan(other coverDelta) bool {
	if c.pairs != other.pairs {
		return c.pairs > other.pairs
	}
	return c.triples > other.triples
}

// By how much the coverage would increase if we append newVal to the row.
// The first integer is the number of newly covered pairs of values,
// the second integer is the number of newly covered triples of values.
func (pc *pairCoverage) wouldCover(row []int, newID, newVal int) coverDelta {
	var pairs, triples int
	for _, item := range rowToPairCombos(row, false, newID, newVal) {
		if _, ok := pc.cover[item]; !ok {
			pairs++
		}
	}
	for _, item := range rowToPairCombos(row, true, newID, newVal) {
		if _, ok := pc.cover[item]; !ok {
			triples++
		}
	}
	return coverDelta{pairs, triples}
}

func (pc *pairCoverage) record(row []int, newID, newVal int) {
	for _, item := range append(
		rowToPairCombos(row, false, newID, newVal),
		rowToPairCombos(row, true, newID, newVal)...) {
		pc.cover[item] = struct{}{}
	}
}

type pair struct {
	pos   int
	value int
}

type pairCombo struct {
	first  pair
	second pair
	third  pair
}

func rowToPairCombos(row []int, triples bool, newID, newVal int) []pairCombo {
	var ret []pairCombo
	// All things being equal, we want to also favor more different values.
	ret = append(ret, pairCombo{third: pair{newID + 1, newVal}})
	for i := 0; i+1 < len(row); i++ {
		if !triples {
			ret = append(ret, pairCombo{
				first: pair{i + 1, row[i]},
				third: pair{newID + 1, newVal},
			})
			continue
		}
		for j := i + 1; j < len(row); j++ {
			ret = append(ret, pairCombo{
				first:  pair{i + 1, row[i]},
				second: pair{j + 1, row[j]},
				third:  pair{newID + 1, newVal},
			})
		}
	}
	return ret
}

func extendRow(row []int, newVal int) []int {
	return append(append([]int{}, row...), newVal)
}
