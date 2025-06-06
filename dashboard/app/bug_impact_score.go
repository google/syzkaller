// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import "regexp"

// impactOrder represent an ordering of bug impact severity. The earlier
// entries are considered more severe.
// The regexps are matched in order, and the first match determines the
// impact category. A higher index in this slice means lower impact.
// The last regexp ".*" is a catch-all for unknown bugs.
var impactOrder = []string{
	// Memory safety.
	`^KASAN:.*Write`,
	`^KASAN:.*Read`,
	`^WARNING: refcount bug`,
	`^UBSAN: array-index`,
	`^BUG: corrupted list`,
	`^BUG: unable to handle kernel paging request`,
	// Memory leaks.
	`^memory leak`,
	// Uninit memory use.
	`^KMSAN:`,
	// Concurrency.
	`^KCSAN:`,
	// Locking.
	`^BUG: sleeping function`,
	`^BUG: spinlock recursion`,
	`^BUG: using ([a-z_]+)\\(\\) in preemptible`,
	`^inconsistent lock state`,
	`^WARNING: still has locks held`,
	`^possible deadlock`,
	`^WARNING: suspicious RCU usage`,
	// Hangs/stalls.
	`^BUG: soft lockup`,
	`^INFO: rcu .* stall`,
	`^INFO: task hung`,
	// DoS.
	`^BUG:`,
	`^kernel BUG`,
	`^divide error`,
	`^Internal error in`,
	`^kernel panic:`,
	`^general protection fault`,
	`.*`,
}

var impactREs = func() []*regexp.Regexp {
	res := make([]*regexp.Regexp, len(impactOrder))
	for i, re := range impactOrder {
		res[i] = regexp.MustCompile(re)
	}
	return res
}()

// TitleToImpact converts a bug title to an impact score.
// A higher score indicates a more severe impact.
// The score is calculated as len(impactOrder) - position of the matching regexp.
func TitleToImpact(title string) int {
	for i, re := range impactREs {
		if re.MatchString(title) {
			return len(impactOrder) - i
		}
	}
	// Should not happen due to the catch-all regexp.
	return -1
}
