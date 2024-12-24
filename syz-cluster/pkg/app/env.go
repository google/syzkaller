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
	storage, err := DefaultStorage()
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

func DefaultStorage() (blob.Storage, error) {
	// LOCAL_BLOB_STORAGE_PATH is set in the dev environment.
	path := os.Getenv("LOCAL_BLOB_STORAGE_PATH")
	if path == "" {
		// TODO: implement GCS support.
		return nil, fmt.Errorf("empty LOCAL_BLOB_STORAGE_PATH")
	}
	err := os.MkdirAll(path, 0666)
	if err != nil {
		return nil, err
	}
	return blob.NewLocalStorage(path), nil
}

func DefaultClient() *api.Client {
	// TODO: take it from some env variable.
	return api.NewClient(`http://controller-service:8080`)
}
