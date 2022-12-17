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
	r := rand.New(testutil.RandSource(t))
	err := testRoundTrip(r, Compress, Decompress)
	if err != nil {
		t.Fatalf("compress/decompress %v", err)
	}
}

func TestEncode(t *testing.T) {
	r := rand.New(testutil.RandSource(t))
	err := testRoundTrip(r, EncodeB64, DecodeB64)
	if err != nil {
		t.Fatalf("encode/decode Base64 %v", err)
	}
}

func testRoundTrip(r *rand.Rand, transform func([]byte) []byte, inverse func([]byte) ([]byte, error)) error {
	for i := 0; i < testutil.IterCount(); i++ {
		randBytes := testutil.RandMountImage(r)
		resultBytes := transform(randBytes)
		resultBytes, err := inverse(resultBytes)
		if err != nil {
			return err
		}
		if !bytes.Equal(randBytes, resultBytes) {
			return fmt.Errorf("roundtrip changes data (original length %d)", len(randBytes))
		}
	}
	return nil
}
