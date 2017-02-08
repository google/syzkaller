// Copyright 2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"bytes"
	"testing"

	"github.com/google/syzkaller/sys"
)

func TestChecksumIP(t *testing.T) {
	tests := []struct {
		data string
		csum uint16
	}{
		{
			"",
			0xffff,
		},
		{
			"\x00",
			0xffff,
		},
		{
			"\x00\x00",
			0xffff,
		},
		{
			"\x00\x00\xff\xff",
			0x0000,
		},
		{
			"\xfc",
			0x03ff,
		},
		{
			"\xfc\x12",
			0x03ed,
		},
		{
			"\xfc\x12\x3e",
			0xc5ec,
		},
		{
			"\xfc\x12\x3e\x00\xc5\xec",
			0x0000,
		},
		{
			"\x42\x00\x00\x43\x44\x00\x00\x00\x45\x00\x00\x00\xba\xaa\xbb\xcc\xdd",
			0xe143,
		},
		{
			"\x00\x00\x42\x00\x00\x43\x44\x00\x00\x00\x45\x00\x00\x00\xba\xaa\xbb\xcc\xdd",
			0xe143,
		},
		{
			"\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x04\x00\xab\xcd",
			0x3250,
		},
		{
			"\x00\x00\x12\x34\x56\x78",
			0x9753,
		},
		{
			"\x00\x00\x12\x34\x00\x00\x56\x78\x00\x06\x00\x04\xab\xcd",
			0xeb7b,
		},
		{
			"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff\xff\xee\xdd\xcc\xbb\xaa\x99\x88\x77\x66\x55\x44\x33\x22\x11\x00\x00\x00\x00\x04\x00\x00\x00\x06\x00\x00\xab\xcd",
			0x5428,
		},
		{
			"\x00\x00\x12\x34\x00\x00\x56\x78\x00\x11\x00\x04\xab\xcd",
			0xeb70,
		},
		{
			"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff\xff\xee\xdd\xcc\xbb\xaa\x99\x88\x77\x66\x55\x44\x33\x22\x11\x00\x00\x00\x00\x04\x00\x00\x00\x11\x00\x00\xab\xcd",
			0x541d,
		},
		{
			"\x00\x11\x22\x33\x44\x55\x66\x77\x88\x99\xaa\xbb\xcc\xdd\xee\xff\xff\xee\xdd\xcc\xbb\xaa\x99\x88\x77\x66\x55\x44\x33\x22\x11\x00\x00\x00\x00\x04\x00\x00\x00\x3a\x00\x00\xab\xcd",
			0x53f4,
		},
	}

	for _, test := range tests {
		csum := ipChecksum([]byte(test.data))
		if csum != test.csum {
			t.Fatalf("incorrect ip checksum, got: %x, want: %x, data: %+v", csum, test.csum, []byte(test.data))
		}
	}
}

func TestChecksumIPAcc(t *testing.T) {
	rs, iters := initTest(t)
	r := newRand(rs)

	for i := 0; i < iters; i++ {
		bytes := make([]byte, r.Intn(256))
		for i := 0; i < len(bytes); i++ {
			bytes[i] = byte(r.Intn(256))
		}
		step := int(r.randRange(1, 8)) * 2
		var csumAcc IPChecksum
		for i := 0; i < len(bytes)/step; i++ {
			csumAcc.Update(bytes[i*step : (i+1)*step])
		}
		if len(bytes)%step != 0 {
			csumAcc.Update(bytes[len(bytes)-(len(bytes)%step) : len(bytes)])
		}
		csum := ipChecksum(bytes)
		if csum != csumAcc.Digest() {
			t.Fatalf("inconsistent ip checksum: %x vs %x, step: %v, data: %+v", csum, csumAcc.Digest(), step, bytes)
		}
	}
}

func TestChecksumEncode(t *testing.T) {
	tests := []struct {
		prog    string
		encoded string
	}{
		{
			"syz_test$csum_encode(&(0x7f0000000000)={0x42, 0x43, [0x44, 0x45], 0xa, 0xb, \"aabbccdd\"})",
			"\x42\x00\x00\x43\x44\x00\x00\x00\x45\x00\x00\x00\xba\xaa\xbb\xcc\xdd",
		},
	}
	for i, test := range tests {
		p, err := Deserialize([]byte(test.prog))
		if err != nil {
			t.Fatalf("failed to deserialize prog %v: %v", test.prog, err)
		}
		encoded := encodeArg(p.Calls[0].Args[0].Res, 0)
		if !bytes.Equal(encoded, []byte(test.encoded)) {
			t.Fatalf("incorrect encoding for prog #%v, got: %+v, want: %+v", i, encoded, []byte(test.encoded))
		}
	}
}

func TestChecksumCalc(t *testing.T) {
	tests := []struct {
		prog string
		kind sys.CsumKind
		csum uint16
	}{
		{
			"syz_test$csum_ipv4(&(0x7f0000000000)={0x0, 0x1234, 0x5678})",
			sys.CsumInet,
			0x9753,
		},
		{
			"syz_test$csum_ipv4_tcp(&(0x7f0000000000)={{0x0, 0x1234, 0x5678}, {{0x0}, \"abcd\"}})",
			sys.CsumPseudo,
			0xeb7b,
		},
		{
			"syz_test$csum_ipv6_tcp(&(0x7f0000000000)={{\"00112233445566778899aabbccddeeff\", \"ffeeddccbbaa99887766554433221100\"}, {{0x0}, \"abcd\"}})",
			sys.CsumPseudo,
			0x5428,
		},
		{
			"syz_test$csum_ipv4_udp(&(0x7f0000000000)={{0x0, 0x1234, 0x5678}, {0x0, \"abcd\"}})",
			sys.CsumPseudo,
			0xeb70,
		},
		{
			"syz_test$csum_ipv6_udp(&(0x7f0000000000)={{\"00112233445566778899aabbccddeeff\", \"ffeeddccbbaa99887766554433221100\"}, {0x0, \"abcd\"}})",
			sys.CsumPseudo,
			0x541d,
		},
		{
			"syz_test$csum_ipv6_icmp(&(0x7f0000000000)={{\"00112233445566778899aabbccddeeff\", \"ffeeddccbbaa99887766554433221100\"}, {0x0, \"abcd\"}})",
			sys.CsumPseudo,
			0x53f4,
		},
	}
	for i, test := range tests {
		p, err := Deserialize([]byte(test.prog))
		if err != nil {
			t.Fatalf("failed to deserialize prog %v: %v", test.prog, err)
		}
		csumMap := calcChecksumsCall(p.Calls[0], i%32)
		found := false
		for oldField, newField := range csumMap {
			if typ, ok := newField.Type.(*sys.CsumType); ok {
				if typ.Kind == test.kind {
					found = true
					csum := newField.Value(i % 32)
					if csum != uintptr(test.csum) {
						t.Fatalf("failed to calc checksum, got %x, want %x, kind %v, prog '%v'", csum, test.csum, test.kind, test.prog)
					}
				}
			} else {
				t.Fatalf("non csum key %+v in csum map %+v", oldField, csumMap)
			}
		}
		if !found {
			t.Fatalf("csum field not found, kind %v, prog '%v'", test.kind, test.prog)
		}
	}
}

func TestChecksumCalcRandom(t *testing.T) {
	rs, iters := initTest(t)
	for i := 0; i < iters; i++ {
		p := Generate(rs, 10, nil)
		for _, call := range p.Calls {
			calcChecksumsCall(call, i%32)
		}
		for try := 0; try <= 10; try++ {
			p.Mutate(rs, 10, nil, nil)
			for _, call := range p.Calls {
				calcChecksumsCall(call, i%32)
			}
		}
	}
}
