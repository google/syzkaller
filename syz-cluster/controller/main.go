// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// NOTE: This app assumes that only one copy of it is runnning at the same time.

package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/google/syzkaller/syz-cluster/pkg/app"
	"github.com/google/syzkaller/syz-cluster/pkg/controller"
	"github.com/google/syzkaller/syz-cluster/pkg/db"
	"github.com/google/syzkaller/syz-cluster/pkg/stats"
	"golang.org/x/sync/errgroup"
)

func main() {
	ctx := context.Background()
	env, err := app.Environment(ctx)
	if err != nil {
		app.Fatalf("failed to set up environment: %v", err)
	}
	g, ctx := errgroup.WithContext(ctx)

	sp := NewSeriesProcessor(env, env.Config)
	g.Go(func() error {
		if err := sp.Loop(ctx); err != nil {
			return fmt.Errorf("processor loop failed: %w", err)
		}
		return nil
	})

	seriesRepo := db.NewSeriesRepository(env.Spanner)
	seriesStatsRepo := db.NewSeriesStatsRepository(env.Spanner)
	statsRepo := db.NewStatsRepository(env.Spanner)
	worker := stats.NewWorker(seriesRepo, seriesStatsRepo, statsRepo, time.Minute)
	g.Go(func() error {
		worker.Loop(ctx)
		return nil
	})

	api := controller.NewAPIServer(env)
	g.Go(func() error {
		log.Printf("listening on port 8080")
		if err := http.ListenAndServe(":8080", api.Mux()); err != nil {
			return fmt.Errorf("listen failed: %w", err)
		}
		return nil
	})

	if err := g.Wait(); err != nil {
		app.Fatalf("app failed: %v", err)
	}
}
