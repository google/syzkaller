// Copyright 2025 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
package prog

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/stretchr/testify/assert"
)

type testCase struct {
	prog            string
	extractArg      func(*Prog) Arg
	regionArray     []any
	relocationTable []any
	payload         []any
}

func TestRoundUpPowerOfTwo(t *testing.T) {
	if res := roundUpPowerOfTwo(9, 8); res != 16 {
		t.Fatalf("expected 16, got %d", res)
	}
	if res := roundUpPowerOfTwo(21, 4); res != 24 {
		t.Fatalf("expected 24, got %d", res)
	}
	if res := roundUpPowerOfTwo(113, 16); res != 128 {
		t.Fatalf("expected 24, got %d", res)
	}
}

func createBuffer(data []any) []byte {
	var buf bytes.Buffer

	for _, d := range data {
		switch val := d.(type) {
		case uint8, uint16, uint32, uint64:
			binary.Write(&buf, binary.LittleEndian, val)
		case []byte:
			buf.Write(val)
		}
	}

	return buf.Bytes()
}

func createPrefix() []byte {
	var prefix bytes.Buffer
	binary.Write(&prefix, binary.LittleEndian, kFuzzTestMagic)
	binary.Write(&prefix, binary.LittleEndian, uint32(0))
	return prefix.Bytes()
}

// nolint:dupl,lll
func TestMarshallKFuzzTestArg(t *testing.T) {
	testCases := []testCase{
		// This test case validates the encoding of the following structure:
		//    msg: ptr[in, msghdr_netlink[netlink_msg_xfrm]] {
		//      msghdr_netlink[netlink_msg_xfrm] {
		//        addr: nil
		//        addrlen: len = 0x0 (4 bytes)
		//        pad = 0x0 (4 bytes)
		//        vec: ptr[in, iovec[in, netlink_msg_xfrm]] {
		//          iovec[in, netlink_msg_xfrm] {
		//            addr: ptr[inout, array[ANYUNION]] {
		//              array[ANYUNION] {
		//              }
		//            }
		//            len: len = 0x33fe0 (8 bytes)
		//          }
		//        }
		//        vlen: const = 0x1 (8 bytes)
		//        ctrl: const = 0x0 (8 bytes)
		//        ctrllen: const = 0x0 (8 bytes)
		//        f: send_flags = 0x0 (4 bytes)
		//        pad = 0x0 (4 bytes)
		//      }
		//    }
		{
			`r0 = openat$cgroup_ro(0xffffffffffffff9c, &(0x7f00000003c0)='cpuacct.stat\x00', 0x26e1, 0x0)
sendmsg$nl_xfrm(r0, &(0x7f0000000240)={0x0, 0x0, &(0x7f0000000080)={&(0x7f00000001c0)=ANY=[], 0x33fe0}}, 0x0)`,
			func(p *Prog) Arg {
				sendMsgCall := p.Calls[1]
				msgHdr := sendMsgCall.Args[1].(*PointerArg).Res
				return msgHdr
			},
			[]any{
				uint32(3), // Num regions.

				// Region definitions: (offset, size) pairs.
				uint32(0), uint32(0x38),
				uint32(0x40), uint32(0x10),
				uint32(0x58), uint32(0x0),
			},
			[]any{
				uint32(3),   // Num entries.
				uint32(0x8), // Bytes of padding.

				// Relocation definitions: (source region, offset, dest region) triplets.
				uint32(0), uint32(0x00), kFuzzTestRegionIDNull,
				uint32(0), uint32(0x10), uint32(1),
				uint32(1), uint32(0x00), uint32(2),
				uint64(0x0), // 8 bytes of padding.
			},
			[]any{
				// Region 0 data.
				kFuzzTestPlaceHolderPtr, // `addr` field, placeholder pointer.
				uint32(0x0),             // `addrlen`.
				uint32(0x0),             // `pad[4]`.
				kFuzzTestPlaceHolderPtr, // `vec` field, placeholder pointer.
				uint64(0x1),             // `vlen`.
				uint64(0x0),             // `ctrl`.
				uint64(0x0),             // `ctrllen`.
				uint32(0x0),             // `f`.
				uint32(0x0),             // `pad[4]`.

				uint64(0x0), // 8 bytes of padding between regions.

				// Region 1 data.
				kFuzzTestPlaceHolderPtr, // `addr` field, placeholder pointer.
				uint64(0x033fe0),        // `len`.

				make([]byte, kFuzzTestPoisonSize), // Inter-region padding.

				[]byte{}, // Region 2 data (empty).

				make([]byte, kFuzzTestPoisonSize), // Tail padding.
			},
		},
		// This test case validates the encoding of the following structure:
		//      loop_info64 {
		//        lo_device: const = 0x0 (8 bytes)
		//        lo_inode: const = 0x0 (8 bytes)
		//        lo_rdevice: const = 0x0 (8 bytes)
		//        lo_offset: int64 = 0x1 (8 bytes)
		//        lo_sizelimit: int64 = 0x8005 (8 bytes)
		//        lo_number: const = 0x0 (4 bytes)
		//        lo_enc_type: lo_encrypt_type = 0x0 (4 bytes)
		//        lo_enc_key_size: int32 = 0x19 (4 bytes)
		//        lo_flags: lo_flags = 0x1c (4 bytes)
		//        lo_file_name: buffer: {ef 35 9f 41 3b b9 38 52 f7 d6 a4 ae 6d dd fb
		//        d1 ce 5d 29 c2 ee 5e 5c a9 00 0f f8 ee 09 e7 37 ff 0e df 11 0f f4 11
		//        76 39 c2 eb 4b 78 c6 60 e6 77 df 70 19 05 b9 aa fa b4 af aa f7 55 a3
		//        f6 a0 04} (length 0x40) lo_crypt_name: buffer: {03 6c 47 c6 78 08 20
		//        d1 cb f7 96 6d 61 fd cf 33 52 63 bd 9b ff bc c2 54 2d ed 71 03 82 59
		//        ca 17 1c e1 a3 11 ef 54 ec 32 d7 1e 14 ef 3d c1 77 e9 b4 8b 00 00 00
		//        00 00 00 00 00 00 00 00 00 00 00} (length 0x40) lo_enc_key: buffer:
		//        {f2 83 59 73 8e 22 9a 4c 66 81 00 00 00 00 00 d3 00 e6 d6 02 00 00
		//        00 00 00 00 00 00 00 00 00 01} (length 0x20) lo_init: array[int64] {
		//          int64 = 0x204 (8 bytes)
		//          int64 = 0x0 (8 bytes)
		//        }
		//      }
		//    }
		//  ]
		{
			`r0 = open(&(0x7f0000000000)='./bus\x00', 0x0, 0x0)
ioctl$LOOP_SET_STATUS64(r0, 0x4c04, &(0x7f0000000540)={0x0, 0x0, 0x0, 0x1, 0x8005, 0x0, 0x0, 0x19, 0x1c, "ef359f413bb93852f7d6a4ae6dddfbd1ce5d29c2ee5e5ca9000ff8ee09e737ff0edf110ff4117639c2eb4b78c660e677df701905b9aafab4afaaf755a3f6a004", "036c47c6780820d1cbf7966d61fdcf335263bd9bffbcc2542ded71038259ca171ce1a311ef54ec32d71e14ef3dc177e9b48b00", "f28359738e229a4c66810000000000d300e6d602000000000000000000000001", [0x204]})`,
			func(p *Prog) Arg {
				ioctlCall := p.Calls[1]
				ptrArg := ioctlCall.Args[2].(*PointerArg)
				ret := ptrArg.Res
				return ret
			},
			[]any{
				uint32(1), // Num regions.

				// Region definitions: (offset, size) pairs.
				uint32(0), uint32(0xe8),
			},
			[]any{
				uint32(0),        // Num entries.
				uint32(12),       // Number of bytes of padding.
				make([]byte, 12), // Padding.
			},
			[]any{
				uint64(0x0),    // `lo_device`.
				uint64(0x0),    // `lo_inode`.
				uint64(0x0),    // `lo_rdevice`.
				uint64(0x1),    // `lo_offset`.
				uint64(0x8005), // `lo_sizelimit`.
				uint32(0x0),    // `lo_number`.
				uint32(0x0),    // `lo_enc_type`.
				uint32(0x19),   // `lo_enc_key_size`.
				uint32(0x1c),   // `lo_flags`.
				[]byte{
					0xef, 0x35, 0x9f, 0x41, 0x3b, 0xb9, 0x38, 0x52,
					0xf7, 0xd6, 0xa4, 0xae, 0x6d, 0xdd, 0xfb, 0xd1,
					0xce, 0x5d, 0x29, 0xc2, 0xee, 0x5e, 0x5c, 0xa9,
					0x00, 0x0f, 0xf8, 0xee, 0x09, 0xe7, 0x37, 0xff,
					0x0e, 0xdf, 0x11, 0x0f, 0xf4, 0x11, 0x76, 0x39,
					0xc2, 0xeb, 0x4b, 0x78, 0xc6, 0x60, 0xe6, 0x77,
					0xdf, 0x70, 0x19, 0x05, 0xb9, 0xaa, 0xfa, 0xb4,
					0xaf, 0xaa, 0xf7, 0x55, 0xa3, 0xf6, 0xa0, 0x04,
				}, // `lo_file_name`.
				[]byte{
					0x03, 0x6c, 0x47, 0xc6, 0x78, 0x08, 0x20, 0xd1,
					0xcb, 0xf7, 0x96, 0x6d, 0x61, 0xfd, 0xcf, 0x33,
					0x52, 0x63, 0xbd, 0x9b, 0xff, 0xbc, 0xc2, 0x54,
					0x2d, 0xed, 0x71, 0x03, 0x82, 0x59, 0xca, 0x17,
					0x1c, 0xe1, 0xa3, 0x11, 0xef, 0x54, 0xec, 0x32,
					0xd7, 0x1e, 0x14, 0xef, 0x3d, 0xc1, 0x77, 0xe9,
					0xb4, 0x8b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				}, // `lo_crypt_name`.
				[]byte{
					0xf2, 0x83, 0x59, 0x73, 0x8e, 0x22, 0x9a, 0x4c,
					0x66, 0x81, 0x00, 0x00, 0x00, 0x00, 0x00, 0xd3,
					0x00, 0xe6, 0xd6, 0x02, 0x00, 0x00, 0x00, 0x00,
					0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
				}, // `lo_enc_key`.
				uint64(0x204), // `lo_init[0].
				uint64(0x0),   // `lo_init[1].

				make([]byte, kFuzzTestPoisonSize), // Tail padding.
			},
		},
	}

	for _, tc := range testCases {
		testOne(t, tc)
	}
}

func testOne(t *testing.T, tc testCase) {
	target, err := GetTarget("linux", "amd64")
	if err != nil {
		t.Fatal(err)
	}
	p, err := target.Deserialize([]byte(tc.prog), NonStrict)
	if err != nil {
		t.Fatal(err)
	}

	arg := tc.extractArg(p)
	encoded := MarshallKFuzztestArg(arg)

	wantPrefix := createPrefix()
	wantRegionArray := createBuffer(tc.regionArray)
	wantRelocTable := createBuffer(tc.relocationTable)
	wantPayload := createBuffer(tc.payload)

	regionArrayLen := len(wantRegionArray)
	relocTableLen := len(wantRelocTable)
	payloadLen := len(wantPayload)

	if len(encoded) != kFuzzTestPrefixSize+regionArrayLen+relocTableLen+payloadLen {
		t.Fatalf("encoded output has wrong total length: got %d, want %d",
			len(encoded), regionArrayLen+relocTableLen+payloadLen)
	}

	gotPrefix := encoded[:kFuzzTestPrefixSize]
	gotRegionArray := encoded[kFuzzTestPrefixSize : kFuzzTestPrefixSize+regionArrayLen]
	gotRelocTable := encoded[kFuzzTestPrefixSize+regionArrayLen : kFuzzTestPrefixSize+regionArrayLen+relocTableLen]
	gotPayload := encoded[kFuzzTestPrefixSize+regionArrayLen+relocTableLen:]

	assert.Equal(t, wantPrefix, gotPrefix)
	assert.Equal(t, wantRegionArray, gotRegionArray)
	assert.Equal(t, wantRelocTable, gotRelocTable)
	assert.Equal(t, wantPayload, gotPayload)
}
