// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package app

import (
	"context"
	"fmt"
	"os"
	"testing"

	"cloud.google.com/go/spanner"
	"github.com/google/syzkaller/syz-cluster/pkg/api"
	"github.com/google/syzkaller/syz-cluster/pkg/blob"
	"github.com/google/syzkaller/syz-cluster/pkg/db"
)

type AppEnvironment struct {
	Spanner     *spanner.Client
	BlobStorage blob.Storage
}

func Environment(ctx context.Context) (*AppEnvironment, error) {
	spanner, err := DefaultSpanner(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to set up a Spanner client: %w", err)
	}
	storage, err := DefaultStorage(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to set up the blob storage: %w", err)
	}
	return &AppEnvironment{
		Spanner:     spanner,
		BlobStorage: storage,
	}, nil
}

func TestEnvironment(t *testing.T) (*AppEnvironment, context.Context) {
	client, ctx := db.NewTransientDB(t)
	return &AppEnvironment{
		Spanner:     client,
		BlobStorage: blob.NewLocalStorage(t.TempDir()),
	}, ctx
}

func DefaultSpannerURI() (db.ParsedURI, error) {
	rawURI := os.Getenv("SPANNER_DATABASE_URI")
	if rawURI == "" {
		return db.ParsedURI{}, fmt.Errorf("no SPANNER_DATABASE_URI is set")
	}
	return db.ParseURI(rawURI)
}

func DefaultSpanner(ctx context.Context) (*spanner.Client, error) {
	uri, err := DefaultSpannerURI()
	if err != nil {
		// Validate the URI early on.
		return nil, err
	}
	return spanner.NewClient(ctx, uri.Full)
}

func DefaultStorage(ctx context.Context) (blob.Storage, error) {
	// BLOB_STORAGE_GCS_BUCKET is the only supported option.
	bucket := os.Getenv("BLOB_STORAGE_GCS_BUCKET")
	if bucket == "" {
		return nil, fmt.Errorf("empty BLOB0_STORAGE_GCS_BUCKET")
	}
	return blob.NewGCSClient(ctx, bucket)
}

func DefaultClient() *api.Client {
	return api.NewClient(`http://controller-service:8080`)
}

func DefaultReporterClient() *api.ReporterClient {
	return api.NewReporterClient(`http://reporter-server-service:8080`)
}
