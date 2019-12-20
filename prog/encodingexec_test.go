// Copyright 2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"reflect"
	"testing"
)

func TestSerializeForExecRandom(t *testing.T) {
	target, rs, iters := initTest(t)
	buf := make([]byte, ExecBufferSize)
	for i := 0; i < iters; i++ {
		p := target.Generate(rs, 10, nil)
		n, err := p.SerializeForExec(buf)
		if err != nil {
			t.Fatalf("failed to serialize: %v", err)
		}
		_, err = target.DeserializeExec(buf[:n])
		if err != nil {
			t.Fatal(err)
		}
	}
}

func TestSerializeForExec(t *testing.T) {
	target := initTargetTest(t, "test", "64")
	var (
		dataOffset = target.DataOffset
		ptrSize    = target.PtrSize
	)
	callID := func(name string) uint64 {
		c := target.SyscallMap[name]
		if c == nil {
			t.Fatalf("unknown syscall %v", name)
		}
		return uint64(c.ID)
	}
	tests := []struct {
		prog       string
		serialized []uint64
		decoded    *ExecProg
	}{
		{
			"test()",
			[]uint64{
				callID("test"), ExecNoCopyout, 0,
				execInstrEOF,
			},
			&ExecProg{
				Calls: []ExecCall{
					{
						Meta:  target.SyscallMap["test"],
						Index: ExecNoCopyout,
					},
				},
			},
		},
		{
			"test$int(0x1, 0x2, 0x3, 0x4, 0x5)",
			[]uint64{
				callID("test$int"), ExecNoCopyout, 5,
				execArgConst, 8, 1,
				execArgConst, 1, 2,
				execArgConst, 2, 3,
				execArgConst, 4, 4,
				execArgConst, 8, 5,
				execInstrEOF,
			},
			nil,
		},
		{
			"test$align0(&(0x7f0000000000)={0x1, 0x2, 0x3, 0x4, 0x5})",
			[]uint64{
				execInstrCopyin, dataOffset + 0, execArgConst, 2, 1,
				execInstrCopyin, dataOffset + 4, execArgConst, 4, 2,
				execInstrCopyin, dataOffset + 8, execArgConst, 1, 3,
				execInstrCopyin, dataOffset + 10, execArgConst, 2, 4,
				execInstrCopyin, dataOffset + 16, execArgConst, 8, 5,
				callID("test$align0"), ExecNoCopyout, 1, execArgConst, ptrSize, dataOffset,
				execInstrEOF,
			},
			nil,
		},
		{
			"test$align1(&(0x7f0000000000)={0x1, 0x2, 0x3, 0x4, 0x5})",
			[]uint64{
				execInstrCopyin, dataOffset + 0, execArgConst, 2, 1,
				execInstrCopyin, dataOffset + 2, execArgConst, 4, 2,
				execInstrCopyin, dataOffset + 6, execArgConst, 1, 3,
				execInstrCopyin, dataOffset + 7, execArgConst, 2, 4,
				execInstrCopyin, dataOffset + 9, execArgConst, 8, 5,
				callID("test$align1"), ExecNoCopyout, 1, execArgConst, ptrSize, dataOffset,
				execInstrEOF,
			},
			nil,
		},
		{
			"test$align2(&(0x7f0000000000)={0x42, {[0x43]}, {[0x44]}})",
			[]uint64{
				execInstrCopyin, dataOffset + 0, execArgConst, 1, 0x42,
				execInstrCopyin, dataOffset + 1, execArgConst, 2, 0x43,
				execInstrCopyin, dataOffset + 4, execArgConst, 2, 0x44,
				callID("test$align2"), ExecNoCopyout, 1, execArgConst, ptrSize, dataOffset,
				execInstrEOF,
			},
			nil,
		},
		{
			"test$align3(&(0x7f0000000000)={0x42, {0x43}, {0x44}})",
			[]uint64{
				execInstrCopyin, dataOffset + 0, execArgConst, 1, 0x42,
				execInstrCopyin, dataOffset + 1, execArgConst, 1, 0x43,
				execInstrCopyin, dataOffset + 4, execArgConst, 1, 0x44,
				callID("test$align3"), ExecNoCopyout, 1, execArgConst, ptrSize, dataOffset,
				execInstrEOF,
			},
			nil,
		},
		{
			"test$align4(&(0x7f0000000000)={{0x42, 0x43}, 0x44})",
			[]uint64{
				execInstrCopyin, dataOffset + 0, execArgConst, 1, 0x42,
				execInstrCopyin, dataOffset + 1, execArgConst, 2, 0x43,
				execInstrCopyin, dataOffset + 4, execArgConst, 1, 0x44,
				callID("test$align4"), ExecNoCopyout, 1, execArgConst, ptrSize, dataOffset,
				execInstrEOF,
			},
			nil,
		},
		{
			"test$align5(&(0x7f0000000000)={{0x42, []}, {0x43, [0x44, 0x45, 0x46]}, 0x47})",
			[]uint64{
				execInstrCopyin, dataOffset + 0, execArgConst, 8, 0x42,
				execInstrCopyin, dataOffset + 8, execArgConst, 8, 0x43,
				execInstrCopyin, dataOffset + 16, execArgConst, 2, 0x44,
				execInstrCopyin, dataOffset + 18, execArgConst, 2, 0x45,
				execInstrCopyin, dataOffset + 20, execArgConst, 2, 0x46,
				execInstrCopyin, dataOffset + 22, execArgConst, 1, 0x47,
				callID("test$align5"), ExecNoCopyout, 1, execArgConst, ptrSize, dataOffset,
				execInstrEOF,
			},
			nil,
		},
		{
			"test$align6(&(0x7f0000000000)={0x42, [0x43]})",
			[]uint64{
				execInstrCopyin, dataOffset + 0, execArgConst, 1, 0x42,
				execInstrCopyin, dataOffset + 4, execArgConst, 4, 0x43,
				callID("test$align6"), ExecNoCopyout, 1, execArgConst, ptrSize, dataOffset,
				execInstrEOF,
			},
			nil,
		},
		{
			"test$union0(&(0x7f0000000000)={0x1, @f2=0x2})",
			[]uint64{
				execInstrCopyin, dataOffset + 0, execArgConst, 8, 1,
				execInstrCopyin, dataOffset + 8, execArgConst, 1, 2,
				callID("test$union0"), ExecNoCopyout, 1, execArgConst, ptrSize, dataOffset,
				execInstrEOF,
			},
			nil,
		},
		{
			"test$union1(&(0x7f0000000000)={@f1=0x42, 0x43})",
			[]uint64{
				execInstrCopyin, dataOffset + 0, execArgConst, 4, 0x42,
				execInstrCopyin, dataOffset + 8, execArgConst, 1, 0x43,
				callID("test$union1"), ExecNoCopyout, 1, execArgConst, ptrSize, dataOffset,
				execInstrEOF,
			},
			nil,
		},
		{
			"test$union2(&(0x7f0000000000)={@f1=0x42, 0x43})",
			[]uint64{
				execInstrCopyin, dataOffset + 0, execArgConst, 4, 0x42,
				execInstrCopyin, dataOffset + 4, execArgConst, 1, 0x43,
				callID("test$union2"), ExecNoCopyout, 1, execArgConst, ptrSize, dataOffset,
				execInstrEOF,
			},
			nil,
		},
		{
			"test$array0(&(0x7f0000000000)={0x1, [@f0=0x2, @f1=0x3], 0x4})",
			[]uint64{
				execInstrCopyin, dataOffset + 0, execArgConst, 1, 1,
				execInstrCopyin, dataOffset + 1, execArgConst, 2, 2,
				execInstrCopyin, dataOffset + 3, execArgConst, 8, 3,
				execInstrCopyin, dataOffset + 11, execArgConst, 8, 4,
				callID("test$array0"), ExecNoCopyout, 1, execArgConst, ptrSize, dataOffset,
				execInstrEOF,
			},
			nil,
		},
		{
			"test$array1(&(0x7f0000000000)={0x42, \"0102030405\"})",
			[]uint64{
				execInstrCopyin, dataOffset + 0, execArgConst, 1, 0x42,
				execInstrCopyin, dataOffset + 1, execArgData, 5, 0x0504030201,
				callID("test$array1"), ExecNoCopyout, 1, execArgConst, ptrSize, dataOffset,
				execInstrEOF,
			},
			nil,
		},
		{
			"test$array2(&(0x7f0000000000)={0x42, \"aaaaaaaabbbbbbbbccccccccdddddddd\", 0x43})",
			[]uint64{
				execInstrCopyin, dataOffset + 0, execArgConst, 2, 0x42,
				execInstrCopyin, dataOffset + 2, execArgData, 16, 0xbbbbbbbbaaaaaaaa, 0xddddddddcccccccc,
				execInstrCopyin, dataOffset + 18, execArgConst, 2, 0x43,
				callID("test$array2"), ExecNoCopyout, 1, execArgConst, ptrSize, dataOffset,
				execInstrEOF,
			},
			nil,
		},
		{
			"test$end0(&(0x7f0000000000)={0x42, 0x42, 0x42, 0x42})",
			[]uint64{
				execInstrCopyin, dataOffset + 0, execArgConst, 1, 0x42,
				execInstrCopyin, dataOffset + 1, execArgConst, 2 | 1<<8, 0x42,
				execInstrCopyin, dataOffset + 3, execArgConst, 4 | 1<<8, 0x42,
				execInstrCopyin, dataOffset + 7, execArgConst, 8 | 1<<8, 0x42,
				callID("test$end0"), ExecNoCopyout, 1, execArgConst, ptrSize, dataOffset,
				execInstrEOF,
			},
			nil,
		},
		{
			"test$end1(&(0x7f0000000000)={0xe, 0x42, 0x1})",
			[]uint64{
				execInstrCopyin, dataOffset + 0, execArgConst, 2 | 1<<8, 0xe,
				execInstrCopyin, dataOffset + 2, execArgConst, 4 | 1<<8, 0x42,
				execInstrCopyin, dataOffset + 6, execArgConst, 8 | 1<<8, 0x1,
				callID("test$end1"), ExecNoCopyout, 1, execArgConst, ptrSize, dataOffset,
				execInstrEOF,
			},
			nil,
		},
		{
			"test$bf0(&(0x7f0000000000)={0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42})",
			[]uint64{
				execInstrCopyin, dataOffset + 0, execArgConst, 2 | 0<<16 | 10<<24, 0x42,
				execInstrCopyin, dataOffset + 8, execArgConst, 8, 0x42,
				execInstrCopyin, dataOffset + 16, execArgConst, 2 | 0<<16 | 5<<24, 0x42,
				execInstrCopyin, dataOffset + 16, execArgConst, 2 | 5<<16 | 6<<24, 0x42,
				execInstrCopyin, dataOffset + 16, execArgConst, 4 | 11<<16 | 15<<24, 0x42,
				execInstrCopyin, dataOffset + 20, execArgConst, 2 | 0<<16 | 11<<24, 0x42,
				execInstrCopyin, dataOffset + 22, execArgConst, 2 | 1<<8 | 0<<16 | 11<<24, 0x42,
				execInstrCopyin, dataOffset + 24, execArgConst, 1, 0x42,
				callID("test$bf0"), ExecNoCopyout, 1, execArgConst, ptrSize, dataOffset,
				execInstrEOF,
			},
			&ExecProg{
				Calls: []ExecCall{
					{
						Meta:  target.SyscallMap["test$bf0"],
						Index: ExecNoCopyout,
						Args: []ExecArg{
							ExecArgConst{
								Size:  ptrSize,
								Value: dataOffset,
							},
						},
						Copyin: []ExecCopyin{
							{
								Addr: dataOffset + 0,
								Arg: ExecArgConst{
									Size:           2,
									Value:          0x42,
									BitfieldOffset: 0,
									BitfieldLength: 10,
								},
							},
							{
								Addr: dataOffset + 8,
								Arg: ExecArgConst{
									Size:  8,
									Value: 0x42,
								},
							},
							{
								Addr: dataOffset + 16,
								Arg: ExecArgConst{
									Size:           2,
									Value:          0x42,
									BitfieldOffset: 0,
									BitfieldLength: 5,
								},
							},
							{
								Addr: dataOffset + 16,
								Arg: ExecArgConst{
									Size:           2,
									Value:          0x42,
									BitfieldOffset: 5,
									BitfieldLength: 6,
								},
							},
							{
								Addr: dataOffset + 16,
								Arg: ExecArgConst{
									Size:           4,
									Value:          0x42,
									BitfieldOffset: 11,
									BitfieldLength: 15,
								},
							},
							{
								Addr: dataOffset + 20,
								Arg: ExecArgConst{
									Size:           2,
									Value:          0x42,
									BitfieldOffset: 0,
									BitfieldLength: 11,
								},
							},
							{
								Addr: dataOffset + 22,
								Arg: ExecArgConst{
									Size:           2,
									Format:         FormatBigEndian,
									Value:          0x42,
									BitfieldOffset: 0,
									BitfieldLength: 11,
								},
							},
							{
								Addr: dataOffset + 24,
								Arg: ExecArgConst{
									Size:  1,
									Value: 0x42,
								},
							},
						},
					},
				},
			},
		},
		{
			"test$bf1(&(0x7f0000000000)={{0x42, 0x42, 0x42}, 0x42})",
			[]uint64{
				execInstrCopyin, dataOffset + 0, execArgConst, 4 | 0<<16 | 10<<24, 0x42,
				execInstrCopyin, dataOffset + 0, execArgConst, 4 | 10<<16 | 10<<24, 0x42,
				execInstrCopyin, dataOffset + 0, execArgConst, 4 | 20<<16 | 10<<24, 0x42,
				execInstrCopyin, dataOffset + 4, execArgConst, 1, 0x42,
				callID("test$bf1"), ExecNoCopyout, 1, execArgConst, ptrSize, dataOffset,
				execInstrEOF,
			},
			nil,
		},
		{
			"test$res1(0xffff)",
			[]uint64{
				callID("test$res1"), ExecNoCopyout, 1, execArgConst, 4, 0xffff,
				execInstrEOF,
			},
			nil,
		},
		{
			"test$opt3(0x0)",
			[]uint64{
				callID("test$opt3"), ExecNoCopyout, 1, execArgConst, 8 | 4<<32, 0x64,
				execInstrEOF,
			},
			nil,
		},
		{
			// Special value that translates to 0 for all procs.
			"test$opt3(0xffffffffffffffff)",
			[]uint64{
				callID("test$opt3"), ExecNoCopyout, 1, execArgConst, 8, 0,
				execInstrEOF,
			},
			nil,
		},
		{
			// NULL pointer must be encoded os 0.
			"test$opt1(0x0)",
			[]uint64{
				callID("test$opt1"), ExecNoCopyout, 1, execArgConst, 8, 0,
				execInstrEOF,
			},
			nil,
		},
		{
			"test$align7(&(0x7f0000000000)={{0x1, 0x2, 0x3, 0x4, 0x5, 0x6}, 0x42})",
			[]uint64{
				execInstrCopyin, dataOffset + 0, execArgConst, 1 | 0<<16 | 1<<24, 0x1,
				execInstrCopyin, dataOffset + 0, execArgConst, 1 | 1<<16 | 1<<24, 0x2,
				execInstrCopyin, dataOffset + 0, execArgConst, 1 | 2<<16 | 1<<24, 0x3,
				execInstrCopyin, dataOffset + 0, execArgConst, 2 | 3<<16 | 1<<24, 0x4,
				execInstrCopyin, dataOffset + 0, execArgConst, 2 | 4<<16 | 1<<24, 0x5,
				execInstrCopyin, dataOffset + 0, execArgConst, 2 | 5<<16 | 1<<24, 0x6,
				execInstrCopyin, dataOffset + 8, execArgConst, 1, 0x42,
				callID("test$align7"), ExecNoCopyout, 1, execArgConst, ptrSize, dataOffset,
				execInstrEOF,
			},
			nil,
		},
		{
			"test$excessive_fields1(0x0)",
			[]uint64{
				callID("test$excessive_fields1"), ExecNoCopyout, 1, execArgConst, ptrSize, 0x0,
				execInstrEOF,
			},
			nil,
		},
		{
			"test$excessive_fields1(0xffffffffffffffff)",
			[]uint64{
				callID("test$excessive_fields1"), ExecNoCopyout, 1, execArgConst, ptrSize, 0xffffffffffffffff,
				execInstrEOF,
			},
			nil,
		},
		{
			"test$excessive_fields1(0xfffffffffffffffe)",
			[]uint64{
				callID("test$excessive_fields1"), ExecNoCopyout, 1, execArgConst, ptrSize, 0x9999999999999999,
				execInstrEOF,
			},
			nil,
		},
		{
			"test$csum_ipv4_tcp(&(0x7f0000000000)={{0x0, 0x1, 0x2}, {{0x0}, \"ab\"}})",
			[]uint64{
				execInstrCopyin, dataOffset + 0, execArgConst, 2, 0x0,
				execInstrCopyin, dataOffset + 2, execArgConst, 4 | 1<<8, 0x1,
				execInstrCopyin, dataOffset + 6, execArgConst, 4 | 1<<8, 0x2,
				execInstrCopyin, dataOffset + 10, execArgConst, 2, 0x0,
				execInstrCopyin, dataOffset + 12, execArgData, 1, 0xab,

				execInstrCopyin, dataOffset + 10, execArgCsum, 2, ExecArgCsumInet, 5,
				ExecArgCsumChunkData, dataOffset + 2, 4,
				ExecArgCsumChunkData, dataOffset + 6, 4,
				ExecArgCsumChunkConst, 0x0600, 2,
				ExecArgCsumChunkConst, 0x0300, 2,
				ExecArgCsumChunkData, dataOffset + 10, 3,
				execInstrCopyin, dataOffset + 0, execArgCsum, 2, ExecArgCsumInet, 1,
				ExecArgCsumChunkData, dataOffset + 0, 10,
				callID("test$csum_ipv4_tcp"), ExecNoCopyout, 1, execArgConst, ptrSize, dataOffset,
				execInstrEOF,
			},
			nil,
		},
	}

	buf := make([]byte, ExecBufferSize)
	for i, test := range tests {
		i, test := i, test
		t.Run(fmt.Sprintf("%v:%v", i, test.prog), func(t *testing.T) {
			p, err := target.Deserialize([]byte(test.prog), Strict)
			if err != nil {
				t.Fatalf("failed to deserialize prog %v: %v", i, err)
			}
			n, err := p.SerializeForExec(buf)
			if err != nil {
				t.Fatalf("failed to serialize: %v", err)
			}
			w := new(bytes.Buffer)
			binary.Write(w, binary.LittleEndian, test.serialized)
			data := buf[:n]
			if !bytes.Equal(data, w.Bytes()) {
				got := make([]uint64, len(data)/8)
				binary.Read(bytes.NewReader(data), binary.LittleEndian, &got)
				t.Logf("want: %v", test.serialized)
				t.Logf("got:  %v", got)
				t.Fatalf("mismatch")
			}
			decoded, err := target.DeserializeExec(data)
			if err != nil {
				t.Fatal(err)
			}
			if test.decoded != nil && !reflect.DeepEqual(decoded, *test.decoded) {
				t.Logf("want: %#v", *test.decoded)
				t.Logf("got:  %#v", decoded)
				t.Fatalf("decoded mismatch")
			}
		})
	}
}
