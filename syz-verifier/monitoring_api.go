// Copyright 2021 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// TODO: switch syz-verifier to use syz-fuzzer.

//go:build never

package main

import (
	"encoding/json"
	"net/http"
	"time"
)

// Monitor provides http based data for the syz-verifier monitoring.
// TODO: Add tests to monitoring_api.
type Monitor struct {
	externalStats *Stats
}

// MakeMonitor creates the Monitor instance.
func MakeMonitor() *Monitor {
	instance := &Monitor{}
	instance.initHTTPHandlers()
	return instance
}

// ListenAndServe starts the server.
func (monitor *Monitor) ListenAndServe(addr string) error {
	return http.ListenAndServe(addr, nil)
}

// SetStatsTracking points Monitor to the Stats object to monitor.
func (monitor *Monitor) SetStatsTracking(s *Stats) {
	monitor.externalStats = s
}

// InitHTTPHandlers initializes the API routing.
func (monitor *Monitor) initHTTPHandlers() {
	http.Handle("/api/stats.json", jsonResponse(monitor.renderStats))

	http.HandleFunc("/", func(writer http.ResponseWriter, request *http.Request) {
		writer.Write([]byte("<a href='api/stats.json'>stats_json</a>"))
	})
}

// statsJSON provides information for the "/api/stats.json" render.
type statsJSON struct {
	StartTime           time.Time
	TotalCallMismatches uint64
	TotalProgs          uint64
	ExecErrorProgs      uint64
	FlakyProgs          uint64
	MismatchingProgs    uint64
	AverExecSpeed       uint64
}

// renderStats renders the statsJSON object.
func (monitor *Monitor) renderStats() interface{} {
	stats := monitor.externalStats

	return &statsJSON{
		StartTime:           stats.StartTime.Get(),
		TotalCallMismatches: stats.TotalCallMismatches.Get(),
		TotalProgs:          stats.TotalProgs.Get(),
		ExecErrorProgs:      stats.ExecErrorProgs.Get(),
		FlakyProgs:          stats.FlakyProgs.Get(),
		MismatchingProgs:    stats.MismatchingProgs.Get(),
		AverExecSpeed:       60 * stats.TotalProgs.Get() / uint64(1+time.Since(stats.StartTime.Get()).Seconds()),
	}
}

// jsonResponse provides general response forming logic.
func jsonResponse(getData func() interface{}) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")

		data := getData()
		json, err := json.MarshalIndent(
			data,
			"",
			"\t",
		)
		if err != nil {
			http.Error(w, err.Error(), 500) // Internal Server Error.
			return
		}

		w.Write(json)
	})
}
