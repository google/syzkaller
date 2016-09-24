// Copyright 2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/google/syzkaller/sys"
)

func TestSerializeForExecRandom(t *testing.T) {
	rs, iters := initTest(t)
	for i := 0; i < iters; i++ {
		p := Generate(rs, 10, nil)
		p.SerializeForExec()
	}
}

func TestSerializeForExec(t *testing.T) {
	tests := []struct {
		prog       string
		serialized []uint64
	}{
		{
			"getpid()",
			[]uint64{uint64(sys.CallMap["getpid"].ID), 0, uint64(ExecInstrEOF)},
		},
	}
	for i, test := range tests {
		p, err := Deserialize([]byte(test.prog))
		if err != nil {
			t.Fatalf("failed to deserialize prog %v: %v", i, err)
		}
		t.Run(fmt.Sprintf("%v:%v", i, p.String()), func(t *testing.T) {
			data := p.SerializeForExec()
			w := new(bytes.Buffer)
			binary.Write(w, binary.LittleEndian, test.serialized)
			if !bytes.Equal(data, w.Bytes()) {
				t.Fatalf("want %+q, got %+q", w.Bytes(), data)
			}

		})
	}
}
