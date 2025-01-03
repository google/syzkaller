// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"cloud.google.com/go/spanner"
	"github.com/google/syzkaller/syz-cluster/pkg/app"
	"github.com/google/syzkaller/syz-cluster/pkg/db"
	"google.golang.org/api/iterator"
)

func runSQL(ctx context.Context, uri db.ParsedURI, command string) error {
	client, err := spanner.NewClient(ctx, uri.Full)
	if err != nil {
		return err
	}
	defer client.Close()
	stmt := spanner.Statement{SQL: command}
	iter := client.Single().Query(ctx, stmt)
	defer iter.Stop()

	for {
		row, err := iter.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return err
		}
		cols := row.ColumnNames()
		fmt.Println(cols)
		for i := 0; i < len(cols); i++ {
			fmt.Printf("\t%s", row.ColumnValue(i))
		}
		fmt.Printf("\n")
	}
	return nil
}

func main() {
	ctx := context.Background()
	uri, err := app.DefaultSpannerURI()
	if err != nil {
		app.Fatalf("failed to get Spanner URI: %v", err)
	}
	if os.Getenv("SPANNER_EMULATOR_HOST") != "" {
		// Should only be done in the test/dev environment.
		log.Printf("check if a Spanner instance is present")
		err = db.CreateSpannerInstance(ctx, uri)
		if err != nil {
			app.Fatalf("failed to create Spanner instance: %v", err)
		}
	}
	log.Printf("check if DB is present")
	err = db.CreateSpannerDB(ctx, uri)
	if err != nil {
		app.Fatalf("failed to create Spanner DB: %v", err)
	}
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "migrate":
			log.Printf("running schema migrations")
			err = db.RunMigrations(ctx, uri.Full)
		case "run":
			if len(os.Args) < 3 {
				app.Fatalf("second argument is the SQL query to run")
			}
			err = runSQL(ctx, uri, os.Args[2])
		default:
			app.Fatalf("unknown command: %s", os.Args[1])
		}
		if err != nil {
			log.Fatal(err)
		}
	}
	log.Printf("finished!")
}
