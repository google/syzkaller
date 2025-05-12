// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"log"
	"net/http"

	"github.com/google/syzkaller/syz-cluster/pkg/app"
	"github.com/google/syzkaller/syz-cluster/pkg/reporter"
)

func main() {
	ctx := context.Background()
	env, err := app.Environment(ctx)
	if err != nil {
		app.Fatalf("failed to set up environment: %v", err)
	}

	generator := reporter.NewGenerator(env)
	go generator.Loop(ctx)

	api := reporter.NewAPIServer(env)
	log.Printf("listening on port 8080")
	app.Fatalf("listen failed: %v", http.ListenAndServe(":8080", api.Mux()))
}
