// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package stats

// TODO: I didn't find the substitution as of Feb 2023. Let's keep it as is while it works.
import "golang.org/x/perf/benchstat" // nolint:all

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
