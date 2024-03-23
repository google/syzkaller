// Copyright 2017 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package report

type windows struct {
	*config
}

func ctorWindows(cfg *config) (reporterImpl, []string, error) {
	ctx := &windows{
		config: cfg,
	}
	return ctx, nil, nil
}

func (ctx *windows) ContainsCrash(output []byte) bool {
	// panic("not implemented")
	return false
}

func (ctx *windows) Parse(output []byte) *Report {
	// panic("not implemented")
	return nil
}

func (ctx *windows) Symbolize(rep *Report) error {
	// panic("not implemented")
	return nil
}
