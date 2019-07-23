// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package report

type stub struct {
	*config
}

func ctorStub(cfg *config) (Reporter, []string, error) {
	ctx := &stub{
		config: cfg,
	}
	return ctx, nil, nil
}

func (ctx *stub) ContainsCrash(output []byte) bool {
	panic("not implemented")
}

func (ctx *stub) Parse(output []byte) *Report {
	panic("not implemented")
}

func (ctx *stub) Symbolize(rep *Report) error {
	panic("not implemented")
}
