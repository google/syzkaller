// Copyright 2018 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"runtime"
	"time"

	"github.com/google/syzkaller/pkg/image"
	"github.com/google/syzkaller/pkg/stat"
)

type Stats struct {
	statCrashes       *stat.Val
	statCrashTypes    *stat.Val
	statSuppressed    *stat.Val
	statUptime        *stat.Val
	statFuzzingTime   *stat.Val
	statAvgBootTime   *stat.Val
	statCoverFiltered *stat.Val
}

func (mgr *Manager) initStats() {
	mgr.statCrashes = stat.New("crashes", "Total number of VM crashes",
		stat.Simple, stat.Prometheus("syz_crash_total"))
	mgr.statCrashTypes = stat.New("crash types", "Number of unique crashes types",
		stat.Simple, stat.NoGraph)
	mgr.statSuppressed = stat.New("suppressed", "Total number of suppressed VM crashes",
		stat.Simple, stat.Graph("crashes"))
	mgr.statFuzzingTime = stat.New("fuzzing", "Total fuzzing time in all VMs (seconds)",
		stat.NoGraph, func(v int, period time.Duration) string { return fmt.Sprintf("%v sec", v/1e9) })
	mgr.statUptime = stat.New("uptime", "Total uptime (seconds)", stat.Simple, stat.NoGraph,
		func() int {
			firstConnect := mgr.firstConnect.Load()
			if firstConnect == 0 {
				return 0
			}
			return int(time.Now().Unix() - firstConnect)
		}, func(v int, period time.Duration) string {
			return fmt.Sprintf("%v sec", v)
		})
	mgr.statAvgBootTime = stat.New("instance restart", "Average VM restart time (sec)",
		stat.NoGraph,
		func() int {
			return int(mgr.pool.BootTime.Value().Seconds())
		},
		func(v int, _ time.Duration) string {
			return fmt.Sprintf("%v sec", v)
		})

	stat.New("heap", "Process heap size (bytes)", stat.Graph("memory"),
		func() int {
			var ms runtime.MemStats
			runtime.ReadMemStats(&ms)
			return int(ms.Alloc)
		}, func(v int, period time.Duration) string {
			return fmt.Sprintf("%v MB", v>>20)
		})
	stat.New("VM", "Process VM size (bytes)", stat.Graph("memory"),
		func() int {
			var ms runtime.MemStats
			runtime.ReadMemStats(&ms)
			return int(ms.Sys - ms.HeapReleased)
		}, func(v int, period time.Duration) string {
			return fmt.Sprintf("%v MB", v>>20)
		})
	stat.New("images memory", "Uncompressed images memory (bytes)", stat.Graph("memory"),
		func() int {
			return int(image.StatMemory.Load())
		}, func(v int, period time.Duration) string {
			return fmt.Sprintf("%v MB", v>>20)
		})
	stat.New("uncompressed images", "Total number of uncompressed images in memory",
		func() int {
			return int(image.StatImages.Load())
		})
	mgr.statCoverFiltered = stat.New("filtered coverage", "", stat.NoGraph)
}
