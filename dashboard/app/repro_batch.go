// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"context"
	"fmt"
	"time"

	"github.com/google/syzkaller/dashboard/dashapi"
	"github.com/google/uuid"
	db "google.golang.org/appengine/v2/datastore"
)

type ReproBatch struct {
	ID        string
	Namespace string
	Source    string
	Created   time.Time
	Total     int
}

type ReproBatchItem struct {
	BatchID    string
	ExternalID string
	Status     string
	BugID      string
	Error      string `datastore:",noindex"`
	Provenance int64  `datastore:",noindex"` // Text key from putText, holds kernel config / qemu args / tools JSON
}

func createReproBatch(ctx context.Context, ns, source string, total int) (*ReproBatch, error) {
	batch := &ReproBatch{
		ID:        uuid.New().String(),
		Namespace: ns,
		Source:    source,
		Created:   timeNow(ctx),
		Total:     total,
	}
	key := db.NewKey(ctx, "ReproBatch", batch.ID, 0, nil)
	if _, err := db.Put(ctx, key, batch); err != nil {
		return nil, fmt.Errorf("failed to put ReproBatch: %w", err)
	}
	return batch, nil
}

// saveReproBatchItem is keyed deterministically on (batchID, externalID) so a retried
// upload for the same item overwrites rather than duplicates.
func saveReproBatchItem(ctx context.Context, batchID string, item *ReproBatchItem) error {
	item.BatchID = batchID
	batchKey := db.NewKey(ctx, "ReproBatch", batchID, 0, nil)
	key := db.NewKey(ctx, "ReproBatchItem", item.ExternalID, 0, batchKey)
	_, err := db.Put(ctx, key, item)
	if err != nil {
		return fmt.Errorf("failed to put ReproBatchItem: %w", err)
	}
	return nil
}

func loadReproBatchStatus(ctx context.Context, ns, batchID string) (*dashapi.ReproBatchStatusResp, error) {
	batchKey := db.NewKey(ctx, "ReproBatch", batchID, 0, nil)
	batch := new(ReproBatch)
	if err := db.Get(ctx, batchKey, batch); err != nil {
		return nil, fmt.Errorf("failed to get batch %q: %w", batchID, err)
	}
	if batch.Namespace != ns {
		return nil, fmt.Errorf("no such batch")
	}
	var items []*ReproBatchItem
	_, err := db.NewQuery("ReproBatchItem").
		Ancestor(batchKey).
		GetAll(ctx, &items)
	if err != nil {
		return nil, fmt.Errorf("failed to query ReproBatchItem: %w", err)
	}
	resp := &dashapi.ReproBatchStatusResp{
		Total:     batch.Total,
		Processed: len(items),
	}
	for _, it := range items {
		resp.Items = append(resp.Items, dashapi.ReproBatchItemStatus{
			ExternalID: it.ExternalID,
			Status:     it.Status,
			BugID:      it.BugID,
			Error:      it.Error,
		})
	}
	return resp, nil
}
