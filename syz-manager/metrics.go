// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"net/http"
	"time"
	"github.com/google/syzkaller/pkg/log"
	"github.com/prometheus/client_golang/prometheus"
	//"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"

)

func (mgr *Manager) fetchMetrics() {
	go func() {
                for {
			execs.Set(float64(mgr.stats.execTotal.get()))
                        time.Sleep(2 * time.Second)
                }
        }()
}

var (
	execs = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "syzkaller_exec_total",
		Help: "Total executions so far",
	})

)

func (mgr *Manager) initMetrics() {
	prometheus.Register(execs)
	mgr.fetchMetrics()
	http.Handle("/", promhttp.Handler())
	// Browsers like to request this, without special handler this goes to / handler.

	log.Logf(0, "Metrics on http://%v/", mgr.cfg.METRICS)
	go func() {
		err := http.ListenAndServe(mgr.cfg.METRICS, nil)
		if err != nil {
			log.Fatalf("failed to listen on %v: %v", mgr.cfg.METRICS, err)
		}
	}()
}
