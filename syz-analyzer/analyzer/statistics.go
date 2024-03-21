package main

import (
	syz_analyzer "github.com/google/syzkaller/syz-analyzer"
	"log"
)

type Statistics struct {
	results    map[int64]map[string]*ExecResult
	total      map[int64]int
	successful map[int64]int
	pools      int
}

type ExecResult struct {
	pool  []int
	count int
}

func initStatistics(pools int) *Statistics {
	stats := &Statistics{
		results:    make(map[int64]map[string]*ExecResult),
		total:      make(map[int64]int),
		successful: make(map[int64]int),
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
		log.Printf("------------------------------------")
		log.Printf("Statistics of task number %d", taskId)
		log.Printf("Total runs: %d", stats.total[taskId])
		log.Printf("Successful runs: %d", stats.successful[taskId])
		log.Printf("Error runs: %d", stats.total[taskId]-stats.successful[taskId])
		log.Printf("Percentage of successful runs: %f%%", float64(stats.successful[taskId]*100)/float64(stats.total[taskId]))
		if stats.results[taskId] == nil {
			continue
		}
		log.Printf("Errors while executing:")
		for output, res := range stats.results[taskId] {
			log.Printf("	This error occurs: %d times", res.count)
			for id, pool := range res.pool {
				if pool == 0 {
					continue
				}
				log.Printf("		In pool %d: %d times", id, pool)
			}
			log.Printf("	Error: %s", output)
		}
	}
	log.Printf("------------------------------------")
}
