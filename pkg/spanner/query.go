// Copyright 2026 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package spanner

import (
	"cloud.google.com/go/spanner"
	"google.golang.org/api/iterator"
)

// ReadRow reads a single row from the iterator and parses it into a struct of type T.
// Returns nil, nil if the iterator is done.
func ReadRow[T any](iter *spanner.RowIterator) (*T, error) {
	row, err := iter.Next()
	if err == iterator.Done {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var obj T
	err = row.ToStruct(&obj)
	if err != nil {
		return nil, err
	}
	return &obj, nil
}

// ReadRows reads all remaining rows from the iterator and parses them into a slice of pointers to T.
func ReadRows[T any](iter *spanner.RowIterator) ([]*T, error) {
	var ret []*T
	if err := spanner.SelectAll(iter, &ret); err != nil {
		return nil, err
	}
	return ret, nil
}
