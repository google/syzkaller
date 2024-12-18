// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package spannerclient

import (
	"context"
	"time"

	"cloud.google.com/go/spanner"
)

type SpannerClient interface {
	Close()
	Apply(ctx context.Context, ms []*spanner.Mutation, opts ...spanner.ApplyOption) (commitTimestamp time.Time, err error)
	Single() ReadOnlyTransaction
}

type ReadOnlyTransaction interface {
	Query(ctx context.Context, statement spanner.Statement) RowIterator
}

type RowIterator interface {
	Next() (Row, error)
	Stop()
}

type Row interface {
	ToStruct(p interface{}) error
}

type SpannerClientProxy struct {
	client *spanner.Client
}

func (proxy *SpannerClientProxy) Close() {
	proxy.client.Close()
}

func (proxy *SpannerClientProxy) Apply(ctx context.Context, ms []*spanner.Mutation, opts ...spanner.ApplyOption,
) (commitTimestamp time.Time, err error) {
	return proxy.client.Apply(ctx, ms, opts...)
}

func (proxy *SpannerClientProxy) Single() ReadOnlyTransaction {
	return &SpannerReadOnlyTransactionProxy{
		readOnlyTransaction: proxy.client.Single(),
	}
}

type SpannerReadOnlyTransactionProxy struct {
	readOnlyTransaction *spanner.ReadOnlyTransaction
}

func (proxy *SpannerReadOnlyTransactionProxy) Query(ctx context.Context, statement spanner.Statement) RowIterator {
	return &SpannerRowIteratorProxy{
		rowIterator: proxy.readOnlyTransaction.Query(ctx, statement),
	}
}

type SpannerRowIteratorProxy struct {
	rowIterator *spanner.RowIterator
}

func (proxy *SpannerRowIteratorProxy) Next() (Row, error) {
	return proxy.rowIterator.Next()
}

func (proxy *SpannerRowIteratorProxy) Stop() {
	proxy.rowIterator.Stop()
}

func NewClient(ctx context.Context, projectID string) (SpannerClient, error) {
	database := "projects/" + projectID + "/instances/syzbot/databases/coverage"
	client, err := spanner.NewClient(ctx, database)
	return &SpannerClientProxy{
		client: client,
	}, err
}
