package main

import (
	"fmt"
	syz_analyzer "github.com/google/syzkaller/syz-analyzer"
	"io"
)

type Statistics struct {
	results    map[int64]map[string]*ExecResult
	total      map[int64]int
	successful map[int64]int
	statsWrite io.Writer
	pools      int
}

type ExecResult struct {
	pool  []int
	count int
}

func initStatistics(pools int, sw io.Writer) *Statistics {
	stats := &Statistics{
		results:    make(map[int64]map[string]*ExecResult),
		total:      make(map[int64]int),
		successful: make(map[int64]int),
		statsWrite: sw,
		pools:      pools,
	}

	return stats
}

func (stats *Statistics) addResult(result *syz_analyzer.ProgramArgs) {
	stats.total[result.TaskID]++
	if result.Error != nil {
		output := string(result.Error[:])
		if stats.results[result.TaskID] == nil {
			stats.results[result.TaskID] = make(map[string]*ExecResult)
		}
		if stats.results[result.TaskID][output] == nil {
			stats.results[result.TaskID][output] = &ExecResult{
				pool: make([]int, stats.pools),
			}
		}

		stats.results[result.TaskID][output].pool[result.Pool]++
		stats.results[result.TaskID][output].count++
	} else {
		stats.successful[result.TaskID]++
	}
}

func (stats *Statistics) printStatistics() {
	for taskId := range stats.total {
		fmt.Fprintf(stats.statsWrite, "------------------------------------\n")
		fmt.Fprintf(stats.statsWrite, "Statistics of task number %d\n", taskId)
		fmt.Fprintf(stats.statsWrite, "Total runs: %d\n", stats.total[taskId])
		fmt.Fprintf(stats.statsWrite, "Successful runs: %d\n", stats.successful[taskId])
		fmt.Fprintf(stats.statsWrite, "Error runs: %d\n", stats.total[taskId]-stats.successful[taskId])
		fmt.Fprintf(stats.statsWrite, "Percentage of successful runs: %f%%\n", float64(stats.successful[taskId]*100)/float64(stats.total[taskId]))
		if stats.results[taskId] == nil {
			continue
		}
		fmt.Fprintf(stats.statsWrite, "Errors while executing:\n")
		for output, res := range stats.results[taskId] {
			fmt.Fprintf(stats.statsWrite, "	This error occurs: %d times\n", res.count)
			for id, pool := range res.pool {
				if pool == 0 {
					continue
				}
				fmt.Fprintf(stats.statsWrite, "		In pool %d: %d times\n", id, pool)
			}
			fmt.Fprintf(stats.statsWrite, "	Error: %s\n", output)
		}
	}
	fmt.Fprintf(stats.statsWrite, "------------------------------------\n")
}
