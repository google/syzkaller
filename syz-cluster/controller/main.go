// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

// NOTE: This app assumes that only one copy of it is runnning at the same time.

package main

import (
	"context"
	"log"
	"net/http"

	"github.com/google/syzkaller/syz-cluster/pkg/app"
	"github.com/google/syzkaller/syz-cluster/pkg/controller"
)

func main() {
	ctx := context.Background()
	env, err := app.Environment(ctx)
	if err != nil {
		app.Fatalf("failed to set up environment: %v", err)
	}
	cfg, err := app.Config()
	if err != nil {
		app.Fatalf("failed to fetch the config: %v", err)
	}
	sp := NewSeriesProcessor(env, cfg)
	go func() {
		err := sp.Loop(ctx)
		app.Fatalf("processor loop failed: %v", err)
	}()
	api := controller.NewAPIServer(env)
	log.Printf("listening on port 8080")
	app.Fatalf("listen failed: %v", http.ListenAndServe(":8080", api.Mux()))
}
