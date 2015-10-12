// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"bytes"
	"fmt"
	"math/rand"
	"testing"
	"time"
)

func initTest(t *testing.T) (rand.Source, int) {
	iters := 10000
	if testing.Short() {
		iters = 100
	}
	seed := int64(time.Now().UnixNano())
	rs := rand.NewSource(seed)
	t.Logf("seed=%v", seed)
	return rs, iters
}

func TestGeneration(t *testing.T) {
	rs, iters := initTest(t)
	for i := 0; i < iters; i++ {
		p := Generate(rs, 20, nil)
		hasGettime, hasSelect := false, false
		for _, c := range p.Calls {
			if c.Meta.Name == "clock_gettime" {
				hasGettime = true
			}
			if c.Meta.Name == "select" {
				hasSelect = true
			}
		}
		if hasGettime && hasSelect {
			fmt.Printf("%s\n\n", p.WriteCSource())
		}
	}
}

func TestSerialize(t *testing.T) {
	rs, iters := initTest(t)
	for i := 0; i < iters; i++ {
		p := Generate(rs, 10, nil)
		data := p.Serialize()
		p1, err := Deserialize(data)
		if err != nil {
			t.Fatalf("failed to deserialize program: %v\n%s", err, data)
		}
		data1 := p1.Serialize()
		if len(p.Calls) != len(p1.Calls) {
			t.Fatalf("different number of calls")
		}
		if !bytes.Equal(data, data1) {
			t.Fatalf("program changed after serialize/deserialize\noriginal:\n%s\n\nnew:\n%s\n", data, data1)
		}
	}
}

func TestSerializeForExec(t *testing.T) {
	rs, iters := initTest(t)
	for i := 0; i < iters; i++ {
		p := Generate(rs, 10, nil)
		p.SerializeForExec()
	}
}

func TestSerializeC(t *testing.T) {
	rs, iters := initTest(t)
	for i := 0; i < iters; i++ {
		p := Generate(rs, 10, nil)
		p.WriteCSource()
	}
}
