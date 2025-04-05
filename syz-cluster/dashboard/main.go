// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"log"
	"net/http"

	"github.com/google/syzkaller/syz-cluster/pkg/app"
)

func main() {
	ctx := context.Background()
	env, err := app.Environment(ctx)
	if err != nil {
		app.Fatalf("failed to set up environment: %v", err)
	}
	handler, err := newHandler(env)
	if err != nil {
		app.Fatalf("failed to set up handler: %v", err)
	}
	log.Printf("listening at port 8081")
	log.Fatal(http.ListenAndServe(":8081", handler.Mux()))
}
