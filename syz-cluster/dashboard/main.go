// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"embed"
	"fmt"
	"io/fs"
	"log"
	"net/http"

	"github.com/google/syzkaller/syz-cluster/pkg/app"
)

//go:embed static
var staticFs embed.FS

func main() {
	ctx := context.Background()
	env, err := app.Environment(ctx)
	if err != nil {
		app.Fatalf("failed to set up environment: %v", err)
	}
	handler, err := NewHandler(env)
	if err != nil {
		app.Fatalf("failed to set up handler: %v", err)
	}
	http.HandleFunc("/series/{id}", handler.seriesInfo)
	http.HandleFunc("/patches/{id}", handler.patchContent)
	http.HandleFunc("/", handler.seriesList)

	staticFiles, err := fs.Sub(staticFs, "static")
	if err != nil {
		app.Fatalf("failed to parse templates: %v", err)
	}
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.FS(staticFiles))))

	fmt.Printf("Listening at port 8081\n")
	log.Fatal(http.ListenAndServe(":8081", nil))
}
