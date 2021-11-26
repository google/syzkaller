// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package stats

import "golang.org/x/perf/benchstat"

// Mann-Whitney U test.
func UTest(old, new *Sample) (pval float64, err error) {
	// Unfortunately we cannot just invoke MannWhitneyUTest from x/perf/benchstat/internal/stats,
	// so we first wrap the data in Metrics.
	mOld := benchstat.Metrics{
		RValues: old.Xs,
	}
	mNew := benchstat.Metrics{
		RValues: new.Xs,
	}
	return benchstat.UTest(&mOld, &mNew)
}
