package stat

import (
	"cmp"
	"slices"
	"strings"
)

func TopKNames(hist map[string]int, k int) []string {
	type StringCount struct {
		name  string
		count int
	}
	var namesCounts []StringCount
	var names []string

	for name, count := range hist {
		namesCounts = append(namesCounts, StringCount{name, count})
	}

	for len(namesCounts) < k {
		namesCounts = append(namesCounts, StringCount{"missing", 0})
	}

	slices.SortStableFunc(namesCounts, func(a, b StringCount) int {
		r := cmp.Compare(a.count, b.count)
		if r == 0 {
			return strings.Compare(a.name, b.name)
		}
		return r
	})
	slices.Reverse(namesCounts)

	for _, val := range namesCounts[:k] {
		names = append(names, val.name)
	}

	return names
}
