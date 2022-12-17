// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package image

import (
	"bytes"
	"fmt"
	"math/rand"
	"testing"

	"github.com/google/syzkaller/pkg/testutil"
)

func TestCompress(t *testing.T) {
	t.Parallel()
	r := rand.New(testutil.RandSource(t))
	for i := 0; i < testutil.IterCount(); i++ {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			randBytes := testutil.RandMountImage(r)
			resultBytes := Compress(randBytes)
			resultBytes, dtor := MustDecompress(resultBytes)
			defer dtor()
			if !bytes.Equal(randBytes, resultBytes) {
				t.Fatalf("roundtrip changes data (length %v->%v)", len(randBytes), len(resultBytes))
			}
		})
	}
}

func TestEncode(t *testing.T) {
	t.Parallel()
	r := rand.New(testutil.RandSource(t))
	for i := 0; i < testutil.IterCount(); i++ {
		randBytes := testutil.RandMountImage(r)
		resultBytes := EncodeB64(randBytes)
		resultBytes, err := DecodeB64(resultBytes)
		if err != nil {
			t.Fatalf("decoding failed: %v", err)
		}
		if !bytes.Equal(randBytes, resultBytes) {
			t.Fatalf("roundtrip changes data (original length %d)", len(randBytes))
		}
	}
}
