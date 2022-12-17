// Copyright 2022 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package image_test

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"math/rand"
	"path/filepath"
	"testing"

	. "github.com/google/syzkaller/pkg/image"
	"github.com/google/syzkaller/pkg/testutil"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys/linux/gen"
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

func BenchmarkDecompress(b *testing.B) {
	// Extract the largest image seed.
	data, err := ioutil.ReadFile(filepath.FromSlash("../../sys/linux/test/syz_mount_image_gfs2_0"))
	if err != nil {
		b.Fatal(err)
	}
	target, err := prog.GetTarget("linux", "amd64")
	if err != nil {
		b.Fatal(err)
	}
	p, err := target.Deserialize(data, prog.Strict)
	if err != nil {
		b.Fatalf("failed to deserialize the program: %v", err)
	}
	compressed := p.Calls[0].Args[6].(*prog.PointerArg).Res.(*prog.DataArg).Data()
	if len(compressed) < 100<<10 {
		b.Fatalf("compressed data is too small: %v", len(compressed))
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		uncompressed, dtor := MustDecompress(compressed)
		if len(uncompressed) < 10<<20 {
			b.Fatalf("uncompressed data is too small: %v", len(uncompressed))
		}
		dtor()
	}
}
