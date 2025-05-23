// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package coveragedb

import (
	"testing"

	"github.com/google/syzkaller/pkg/coveragedb/mocks"
	"github.com/stretchr/testify/mock"
	"google.golang.org/api/iterator"
)

func NewRowIteratorMock[K any](t *testing.T, cov []*K,
) *mocks.RowIterator {
	m := mocks.NewRowIterator(t)
	m.On("Stop").Once().Return()
	for _, item := range cov {
		mRow := mocks.NewRow(t)
		mRow.On("ToStruct", mock.Anything).
			Run(func(args mock.Arguments) {
				arg := args.Get(0).(*K)
				*arg = *item
			}).
			Return(nil).Once()

		m.On("Next").
			Return(mRow, nil).Once()
	}

	m.On("Next").
		Return(nil, iterator.Done).Once()
	return m
}
