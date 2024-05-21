// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"runtime"
	"time"

	"github.com/google/syzkaller/pkg/stats"
)

type Stats struct {
	statNumReproducing *stats.Val
	statExecs          *stats.Val
	statCrashes        *stats.Val
	statCrashTypes     *stats.Val
	statSuppressed     *stats.Val
	statUptime         *stats.Val
	statFuzzingTime    *stats.Val
	statAvgBootTime    *stats.Val
}

func (mgr *Manager) initStats() {
	mgr.statNumReproducing = stats.Create("reproducing", "Number of crashes being reproduced",
		stats.Console, stats.NoGraph)
	mgr.statExecs = stats.Create("exec total", "Total test program executions",
		stats.Console, stats.Rate{}, stats.Prometheus("syz_exec_total"))
	mgr.statCrashes = stats.Create("crashes", "Total number of VM crashes",
		stats.Simple, stats.Prometheus("syz_crash_total"))
	mgr.statCrashTypes = stats.Create("crash types", "Number of unique crashes types",
		stats.Simple, stats.NoGraph)
	mgr.statSuppressed = stats.Create("suppressed", "Total number of suppressed VM crashes",
		stats.Simple, stats.Graph("crashes"))
	mgr.statFuzzingTime = stats.Create("fuzzing", "Total fuzzing time in all VMs (seconds)",
		stats.NoGraph, func(v int, period time.Duration) string { return fmt.Sprintf("%v sec", v/1e9) })
	mgr.statUptime = stats.Create("uptime", "Total uptime (seconds)", stats.Simple, stats.NoGraph,
		func() int {
			firstConnect := mgr.firstConnect.Load()
			if firstConnect == 0 {
				return 0
			}
			return int(time.Now().Unix() - firstConnect)
		}, func(v int, period time.Duration) string {
			return fmt.Sprintf("%v sec", v)
		})
	mgr.statAvgBootTime = stats.Create("instance restart", "Average VM restart time (sec)",
		stats.NoGraph,
		func() int {
			return int(mgr.bootTime.Value().Seconds())
		},
		func(v int, _ time.Duration) string {
			return fmt.Sprintf("%v sec", v)
		})

	stats.Create("heap", "Process heap size (bytes)", stats.Graph("memory"),
		func() int {
			var ms runtime.MemStats
			runtime.ReadMemStats(&ms)
			return int(ms.Alloc)
		}, func(v int, period time.Duration) string {
			return fmt.Sprintf("%v MB", v>>20)
		})
	stats.Create("VM", "Process VM size (bytes)", stats.Graph("memory"),
		func() int {
			var ms runtime.MemStats
			runtime.ReadMemStats(&ms)
			return int(ms.Sys - ms.HeapReleased)
		}, func(v int, period time.Duration) string {
			return fmt.Sprintf("%v MB", v>>20)
		})
}
