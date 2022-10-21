// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"bytes"
	"fmt"
	"math/rand"
	"testing"
)

func TestCompress(t *testing.T) {
	r := rand.New(randSource(t))
	err := testRoundTrip(r, Compress, Decompress)
	if err != nil {
		t.Fatalf("compress/decompress %v", err)
	}
}

func TestEncode(t *testing.T) {
	r := rand.New(randSource(t))
	err := testRoundTrip(r, EncodeB64, DecodeB64)
	if err != nil {
		t.Fatalf("encode/decode Base64 %v", err)
	}
}

func testRoundTrip(r *rand.Rand, transform func([]byte) []byte, inverse func([]byte) ([]byte, error)) error {
	for i := 0; i < iterCount(); i++ {
		randBytes := randomBytes(r)
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

func randomBytes(r *rand.Rand) []byte {
	const maxLen = 1 << 20 // 1 MB.
	len := r.Intn(maxLen)
	slice := make([]byte, len)
	r.Read(slice)
	return slice
}
