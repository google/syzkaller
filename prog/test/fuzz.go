// Copyright 2019 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package test

import (
	"bytes"
	"fmt"
	"math/rand"

	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys/test/gen" // import the target we use for fuzzing
)

func FuzzDeserialize(data []byte) int {
	p0, err0 := fuzzTarget.Deserialize(data, prog.NonStrict)
	p1, err1 := fuzzTarget.Deserialize(data, prog.Strict)
	if p0 == nil {
		if p1 != nil {
			panic("NonStrict is stricter than Strict")
		}
		if err0 == nil || err1 == nil {
			panic("no error")
		}
		return 0
	}
	if err0 != nil {
		panic("got program and error")
	}
	data0 := p0.Serialize()
	if p1 != nil {
		if err1 != nil {
			panic("got program and error")
		}
		if !bytes.Equal(data0, p1.Serialize()) {
			panic("got different data")
		}
	}
	p2, err2 := fuzzTarget.Deserialize(data0, prog.NonStrict)
	if err2 != nil {
		panic(fmt.Sprintf("failed to parse serialized: %v\n%s", err2, data0))
	}
	if !bytes.Equal(data0, p2.Serialize()) {
		panic("got different data")
	}
	p3 := p0.Clone()
	if !bytes.Equal(data0, p3.Serialize()) {
		panic("got different data")
	}
	if n, err := p0.SerializeForExec(fuzzBuffer); err == nil {
		if _, err := fuzzTarget.DeserializeExec(fuzzBuffer[:n]); err != nil {
			panic(err)
		}
	}
	p3.Mutate(rand.NewSource(0), 3, fuzzChoiceTable, nil)
	return 0
}

func FuzzParseLog(data []byte) int {
	if len(fuzzTarget.ParseLog(data)) != 0 {
		return 1
	}
	return 0
}

var fuzzBuffer = make([]byte, prog.ExecBufferSize)
var fuzzTarget, fuzzChoiceTable = func() (*prog.Target, *prog.ChoiceTable) {
	prog.Debug()
	target, err := prog.GetTarget("test", "64")
	if err != nil {
		panic(err)
	}
	return target, target.DefaultChoiceTable()
}()
