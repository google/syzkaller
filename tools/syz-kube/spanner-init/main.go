// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"cloud.google.com/go/spanner/admin/database/apiv1/databasepb"
	"github.com/google/syzkaller/pkg/coveragedb"
	pkgspanner "github.com/google/syzkaller/pkg/spanner"
)

func main() {
	var (
		flagURI = flag.String("spanner-uri", "projects/syzkaller/instances/syzkaller/databases/coverage",
			"full Spanner database URI")
	)
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	parsedURI, err := pkgspanner.ParseURI(*flagURI)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to parse spanner uri %q: %v\n", *flagURI, err)
		os.Exit(1)
	}

	fmt.Printf("initializing spanner instance %q...\n", parsedURI.Instance)
	if err := pkgspanner.CreateSpannerInstance(ctx, parsedURI); err != nil {
		fmt.Fprintf(os.Stderr, "failed to create spanner instance: %v\n", err)
		os.Exit(1)
	}

	schema, err := coveragedb.GetSchema()
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to get coverage schema: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("initializing spanner database %q with schema...\n", parsedURI.Database)
	if err := pkgspanner.CreateSpannerDB(ctx, parsedURI, databasepb.DatabaseDialect_POSTGRESQL, schema); err != nil {
		fmt.Fprintf(os.Stderr, "failed to create spanner database: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("spanner database %q successfully initialized\n", *flagURI)
}
