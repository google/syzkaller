// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package report

import "github.com/stretchr/testify/mock"

type testMock struct {
	mock.Mock
	*config
}

func ctorMock(cfg *config) (reporterImpl, []string, error) {
	ctx := &testMock{
		config: cfg,
	}
	return ctx, nil, nil
}

func (ctx *testMock) ContainsCrash(output []byte) bool {
	ret := ctx.Called(output)
	return ret.Get(0).(bool)
}

func (ctx *testMock) Parse(output []byte) *Report {
	ret := ctx.Called(output)
	return ret.Get(0).(*Report)
}

func (ctx *testMock) Symbolize(rep *Report) error {
	ret := ctx.Called(rep)
	return ret.Get(0).(error)
}
