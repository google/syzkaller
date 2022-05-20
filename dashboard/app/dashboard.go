// Copyright 2019 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"cloud.google.com/go/profiler"
	"github.com/google/syzkaller/pkg/log"
	"google.golang.org/appengine/v2"
)

// Doc on https://cloud.google.com/profiler/docs/profiling-go#using-profiler
func enableProfiling() {
	// Profiler initialization, best done as early as possible.
	if err := profiler.Start(profiler.Config{
		// Service and ServiceVersion can be automatically inferred when running
		// on App Engine.
		// ProjectID must be set if not running on GCP.
		// ProjectID: "my-project",
	}); err != nil {
		log.Logf(0, "failed to start profiler: %v", err)
	}
}

func main() {
	enableProfiling()
	installConfig(mainConfig)
	appengine.Main()
}
