// Copyright 2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package prog

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"reflect"
	"testing"

	"github.com/VividCortex/gohistogram"
)

func TestSerializeForExecRandom(t *testing.T) {
	target, rs, iters := initTest(t)
	ct := target.DefaultChoiceTable()
	execSizes := gohistogram.NewHistogram(1000)
	textSizes := gohistogram.NewHistogram(1000)
	totalSize := 0
	sizes := make(map[string]int)
	for i := 0; i < iters; i++ {
		p := target.Generate(rs, 10, ct)
		buf, err := p.SerializeForExec()
		if err != nil {
			t.Fatalf("failed to serialize: %v", err)
		}
		got, err := target.DeserializeExec(buf, sizes)
		if err != nil {
			t.Fatal(err)
		}
		if n, err := ExecCallCount(buf); err != nil {
			t.Fatal(err)
		} else if n != len(got.Calls) {
			t.Fatalf("mismatching number of calls: %v/%v", n, len(got.Calls))
		}
		totalSize += len(buf)
		execSizes.Add(float64(len(buf)))
		textSizes.Add(float64(len(p.Serialize())))
	}
	t.Logf("exec sizes: 10%%:%v 50%%:%v 90%%:%v",
		int(execSizes.Quantile(0.1)), int(execSizes.Quantile(0.5)), int(execSizes.Quantile(0.9)))
	t.Logf("text sizes: 10%%:%v 50%%:%v 90%%:%v",
		int(textSizes.Quantile(0.1)), int(textSizes.Quantile(0.5)), int(textSizes.Quantile(0.9)))
	for what, size := range sizes {
		t.Logf("%-24v: %5.2f%%", what, float64(size)/float64(totalSize)*100)
	}
}

// nolint: funlen
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
		serialized []any
		decoded    *ExecProg
	}{
		{
			"test()",
			[]any{
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
			[]any{
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
			[]any{
				execInstrCopyin, 0, execArgConst, 2, 1,
				execInstrCopyin, 4, execArgConst, 4, 2,
				execInstrCopyin, 8, execArgConst, 1, 3,
				execInstrCopyin, 10, execArgConst, 2, 4,
				execInstrCopyin, 16, execArgConst, 8, 5,
				callID("test$align0"), ExecNoCopyout, 1, execArgAddr64, 0,
				execInstrEOF,
			},
			nil,
		},
		{
			"test$align1(&(0x7f0000000000)={0x1, 0x2, 0x3, 0x4, 0x5})",
			[]any{
				execInstrCopyin, 0, execArgConst, 2, 1,
				execInstrCopyin, 2, execArgConst, 4, 2,
				execInstrCopyin, 6, execArgConst, 1, 3,
				execInstrCopyin, 7, execArgConst, 2, 4,
				execInstrCopyin, 9, execArgConst, 8, 5,
				callID("test$align1"), ExecNoCopyout, 1, execArgAddr64, 0,
				execInstrEOF,
			},
			nil,
		},
		{
			"test$align2(&(0x7f0000000000)={0x42, {[0x43]}, {[0x44]}})",
			[]any{
				execInstrCopyin, 0, execArgConst, 1, 0x42,
				execInstrCopyin, 1, execArgConst, 2, 0x43,
				execInstrCopyin, 4, execArgConst, 2, 0x44,
				callID("test$align2"), ExecNoCopyout, 1, execArgAddr64, 0,
				execInstrEOF,
			},
			nil,
		},
		{
			"test$align3(&(0x7f0000000000)={0x42, {0x43}, {0x44}})",
			[]any{
				execInstrCopyin, 0, execArgConst, 1, 0x42,
				execInstrCopyin, 1, execArgConst, 1, 0x43,
				execInstrCopyin, 4, execArgConst, 1, 0x44,
				callID("test$align3"), ExecNoCopyout, 1, execArgAddr64, 0,
				execInstrEOF,
			},
			nil,
		},
		{
			"test$align4(&(0x7f0000000000)={{0x42, 0x43}, 0x44})",
			[]any{
				execInstrCopyin, 0, execArgConst, 1, 0x42,
				execInstrCopyin, 1, execArgConst, 2, 0x43,
				execInstrCopyin, 4, execArgConst, 1, 0x44,
				callID("test$align4"), ExecNoCopyout, 1, execArgAddr64, 0,
				execInstrEOF,
			},
			nil,
		},
		{
			"test$align5(&(0x7f0000000000)={{0x42, []}, {0x43, [0x44, 0x45, 0x46]}, 0x47})",
			[]any{
				execInstrCopyin, 0, execArgConst, 8, 0x42,
				execInstrCopyin, 8, execArgConst, 8, 0x43,
				execInstrCopyin, 16, execArgConst, 2, 0x44,
				execInstrCopyin, 18, execArgConst, 2, 0x45,
				execInstrCopyin, 20, execArgConst, 2, 0x46,
				execInstrCopyin, 22, execArgConst, 1, 0x47,
				callID("test$align5"), ExecNoCopyout, 1, execArgAddr64, 0,
				execInstrEOF,
			},
			nil,
		},
		{
			"test$align6(&(0x7f0000000000)={0x42, [0x43]})",
			[]any{
				execInstrCopyin, 0, execArgConst, 1, 0x42,
				execInstrCopyin, 4, execArgConst, 4, 0x43,
				callID("test$align6"), ExecNoCopyout, 1, execArgAddr64, 0,
				execInstrEOF,
			},
			nil,
		},
		{
			"test$union0(&(0x7f0000000000)={0x1, @f2=0x2})",
			[]any{
				execInstrCopyin, 0, execArgConst, 8, 1,
				execInstrCopyin, 8, execArgConst, 1, 2,
				callID("test$union0"), ExecNoCopyout, 1, execArgAddr64, 0,
				execInstrEOF,
			},
			nil,
		},
		{
			"test$union1(&(0x7f0000000000)={@f1=0x42, 0x43})",
			[]any{
				execInstrCopyin, 0, execArgConst, 4, 0x42,
				execInstrCopyin, 8, execArgConst, 1, 0x43,
				callID("test$union1"), ExecNoCopyout, 1, execArgAddr64, 0,
				execInstrEOF,
			},
			nil,
		},
		{
			"test$union2(&(0x7f0000000000)={@f1=0x42, 0x43})",
			[]any{
				execInstrCopyin, 0, execArgConst, 4, 0x42,
				execInstrCopyin, 4, execArgConst, 1, 0x43,
				callID("test$union2"), ExecNoCopyout, 1, execArgAddr64, 0,
				execInstrEOF,
			},
			nil,
		},
		{
			"test$array0(&(0x7f0000000000)={0x1, [@f0=0x2, @f1=0x3], 0x4})",
			[]any{
				execInstrCopyin, 0, execArgConst, 1, 1,
				execInstrCopyin, 1, execArgConst, 2, 2,
				execInstrCopyin, 3, execArgConst, 8, 3,
				execInstrCopyin, 11, execArgConst, 8, 4,
				callID("test$array0"), ExecNoCopyout, 1, execArgAddr64, 0,
				execInstrEOF,
			},
			nil,
		},
		{
			"test$array1(&(0x7f0000000000)={0x42, \"0102030405\"})",
			[]any{
				execInstrCopyin, 0, execArgConst, 1, 0x42,
				execInstrCopyin, 1, execArgData, 5, []byte{0x01, 0x02, 0x03, 0x04, 0x05},
				callID("test$array1"), ExecNoCopyout, 1, execArgAddr64, 0,
				execInstrEOF,
			},
			nil,
		},
		{
			"test$array2(&(0x7f0000000000)={0x42, \"aaaaaaaabbbbbbbbccccccccdddddddd\", 0x43})",
			[]any{
				execInstrCopyin, 0, execArgConst, 2, 0x42,
				execInstrCopyin, 2, execArgData, 16, []byte{
					0xaa, 0xaa, 0xaa, 0xaa,
					0xbb, 0xbb, 0xbb, 0xbb,
					0xcc, 0xcc, 0xcc, 0xcc,
					0xdd, 0xdd, 0xdd, 0xdd,
				},
				execInstrCopyin, 18, execArgConst, 2, 0x43,
				callID("test$array2"), ExecNoCopyout, 1, execArgAddr64, 0,
				execInstrEOF,
			},
			nil,
		},
		{
			"test$end0(&(0x7f0000000000)={0x42, 0x42, 0x42, 0x42})",
			[]any{
				execInstrCopyin, 0, execArgConst, 1, 0x42,
				execInstrCopyin, 1, execArgConst, 2 | 1<<8, 0x42,
				execInstrCopyin, 3, execArgConst, 4 | 1<<8, 0x42,
				execInstrCopyin, 7, execArgConst, 8 | 1<<8, 0x42,
				callID("test$end0"), ExecNoCopyout, 1, execArgAddr64, 0,
				execInstrEOF,
			},
			nil,
		},
		{
			"test$end1(&(0x7f0000000000)={0xe, 0x42, 0x1})",
			[]any{
				execInstrCopyin, 0, execArgConst, 2 | 1<<8, 0xe,
				execInstrCopyin, 2, execArgConst, 4 | 1<<8, 0x42,
				execInstrCopyin, 6, execArgConst, 8 | 1<<8, 0x1,
				callID("test$end1"), ExecNoCopyout, 1, execArgAddr64, 0,
				execInstrEOF,
			},
			nil,
		},
		{
			"test$bf0(&(0x7f0000000000)={0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42, 0x42})",
			[]any{
				execInstrCopyin, 0, execArgConst, 2 | 0<<16 | 10<<24, 0x42,
				execInstrCopyin, 8, execArgConst, 8, 0x42,
				execInstrCopyin, 16, execArgConst, 2 | 0<<16 | 5<<24, 0x42,
				execInstrCopyin, 16, execArgConst, 2 | 5<<16 | 6<<24, 0x42,
				execInstrCopyin, 16, execArgConst, 4 | 11<<16 | 15<<24, 0x42,
				execInstrCopyin, 20, execArgConst, 2 | 0<<16 | 11<<24, 0x42,
				execInstrCopyin, 22, execArgConst, 2 | 1<<8 | 0<<16 | 11<<24, 0x42,
				execInstrCopyin, 24, execArgConst, 1, 0x42,
				callID("test$bf0"), ExecNoCopyout, 1, execArgAddr64, 0,
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
			[]any{
				execInstrCopyin, 0, execArgConst, 4 | 0<<16 | 10<<24, 0x42,
				execInstrCopyin, 0, execArgConst, 4 | 10<<16 | 10<<24, 0x42,
				execInstrCopyin, 0, execArgConst, 4 | 20<<16 | 10<<24, 0x42,
				execInstrCopyin, 4, execArgConst, 1, 0x42,
				callID("test$bf1"), ExecNoCopyout, 1, execArgAddr64, 0,
				execInstrEOF,
			},
			nil,
		},
		{
			"test$res1(0xffff)",
			[]any{
				callID("test$res1"), ExecNoCopyout, 1, execArgConst, 4, 0xffff,
				execInstrEOF,
			},
			nil,
		},
		{
			"test$opt3(0x0)",
			[]any{
				callID("test$opt3"), ExecNoCopyout, 1, execArgConst, 8 | 4<<32, 0x64,
				execInstrEOF,
			},
			nil,
		},
		{
			// Special value that translates to 0 for all procs.
			"test$opt3(0xffffffffffffffff)",
			[]any{
				callID("test$opt3"), ExecNoCopyout, 1, execArgConst, 8, 0,
				execInstrEOF,
			},
			nil,
		},
		{
			// NULL pointer must be encoded os 0.
			"test$opt1(0x0)",
			[]any{
				callID("test$opt1"), ExecNoCopyout, 1, execArgAddr64, -dataOffset,
				execInstrEOF,
			},
			nil,
		},
		{
			"test$align7(&(0x7f0000000000)={{0x1, 0x2, 0x3, 0x4, 0x5, 0x6}, 0x42})",
			[]any{
				execInstrCopyin, 0, execArgConst, 1 | 0<<16 | 1<<24, 0x1,
				execInstrCopyin, 0, execArgConst, 1 | 1<<16 | 1<<24, 0x2,
				execInstrCopyin, 0, execArgConst, 1 | 2<<16 | 1<<24, 0x3,
				execInstrCopyin, 0, execArgConst, 2 | 3<<16 | 1<<24, 0x4,
				execInstrCopyin, 0, execArgConst, 2 | 4<<16 | 1<<24, 0x5,
				execInstrCopyin, 0, execArgConst, 2 | 5<<16 | 1<<24, 0x6,
				execInstrCopyin, 8, execArgConst, 1, 0x42,
				callID("test$align7"), ExecNoCopyout, 1, execArgAddr64, 0,
				execInstrEOF,
			},
			nil,
		},
		{
			"test$excessive_fields1(0x0)",
			[]any{
				callID("test$excessive_fields1"), ExecNoCopyout, 1, execArgAddr64, -dataOffset,
				execInstrEOF,
			},
			nil,
		},
		{
			"test$excessive_fields1(0xffffffffffffffff)",
			[]any{
				callID("test$excessive_fields1"), ExecNoCopyout, 1, execArgAddr64, 0xffffffffffffffff - dataOffset,
				execInstrEOF,
			},
			nil,
		},
		{
			"test$excessive_fields1(0xfffffffffffffffe)",
			[]any{
				callID("test$excessive_fields1"), ExecNoCopyout, 1, execArgAddr64, 0x9999999999999999 - dataOffset,
				execInstrEOF,
			},
			nil,
		},
		{
			"test$csum_ipv4_tcp(&(0x7f0000000000)={{0x0, 0x1, 0x2}, {{0x0}, \"ab\"}})",
			[]any{
				execInstrCopyin, 0, execArgConst, 2, 0x0,
				execInstrCopyin, 2, execArgConst, 4 | 1<<8, 0x1,
				execInstrCopyin, 6, execArgConst, 4 | 1<<8, 0x2,
				execInstrCopyin, 10, execArgConst, 2, 0x0,
				execInstrCopyin, 12, execArgData, 1, []byte{0xab},
				execInstrCopyin, 10, execArgCsum, 2, ExecArgCsumInet, 5,
				ExecArgCsumChunkData, 2, 4,
				ExecArgCsumChunkData, 6, 4,
				ExecArgCsumChunkConst, 0x0600, 2,
				ExecArgCsumChunkConst, 0x0300, 2,
				ExecArgCsumChunkData, 10, 3,
				execInstrCopyin, 0, execArgCsum, 2, ExecArgCsumInet, 1,
				ExecArgCsumChunkData, 0, 10,
				callID("test$csum_ipv4_tcp"), ExecNoCopyout, 1, execArgAddr64, 0,
				execInstrEOF,
			},
			&ExecProg{
				Calls: []ExecCall{
					{
						Meta:  target.SyscallMap["test$csum_ipv4_tcp"],
						Index: ExecNoCopyout,
						Args: []ExecArg{
							ExecArgConst{
								Value: dataOffset,
								Size:  8,
							},
						},
						Copyin: []ExecCopyin{
							{
								Addr: dataOffset,
								Arg: ExecArgConst{
									Value: 0,
									Size:  2,
								},
							},
							{
								Addr: dataOffset + 2,
								Arg: ExecArgConst{
									Value:  1,
									Size:   4,
									Format: FormatBigEndian,
								},
							},
							{
								Addr: dataOffset + 6,
								Arg: ExecArgConst{
									Value:  2,
									Size:   4,
									Format: FormatBigEndian,
								},
							},
							{
								Addr: dataOffset + 10,
								Arg: ExecArgConst{
									Value: 0,
									Size:  2,
								},
							},
							{
								Addr: dataOffset + 12,
								Arg: ExecArgData{
									Data: []byte{0xab},
								},
							},
							{
								Addr: dataOffset + 10,
								Arg: ExecArgCsum{
									Size: 2,
									Kind: ExecArgCsumInet,
									Chunks: []ExecCsumChunk{
										{
											Kind:  ExecArgCsumChunkData,
											Value: dataOffset + 2,
											Size:  4,
										},
										{
											Kind:  ExecArgCsumChunkData,
											Value: dataOffset + 6,
											Size:  4,
										},
										{
											Kind:  ExecArgCsumChunkConst,
											Value: 0x0600,
											Size:  2,
										},
										{
											Kind:  ExecArgCsumChunkConst,
											Value: 0x0300,
											Size:  2,
										},
										{
											Kind:  ExecArgCsumChunkData,
											Value: dataOffset + 10,
											Size:  3,
										},
									},
								},
							},
							{
								Addr: dataOffset,
								Arg: ExecArgCsum{
									Size: 2,
									Kind: ExecArgCsumInet,
									Chunks: []ExecCsumChunk{
										{
											Kind:  ExecArgCsumChunkData,
											Value: dataOffset,
											Size:  10,
										},
									},
								},
							},
						},
					},
				},
			},
		},
		{
			`test() (fail_nth: 3)
test() (fail_nth: 4)
test() (async, rerun: 10)
`,
			[]any{
				execInstrSetProps, 3, 0, 0,
				callID("test"), ExecNoCopyout, 0,
				execInstrSetProps, 4, 0, 0,
				callID("test"), ExecNoCopyout, 0,
				execInstrSetProps, 0, 1, 10,
				callID("test"), ExecNoCopyout, 0,
				execInstrEOF,
			},
			&ExecProg{
				Calls: []ExecCall{
					{
						Meta:  target.SyscallMap["test"],
						Index: ExecNoCopyout,
						Props: CallProps{3, false, 0},
					},
					{
						Meta:  target.SyscallMap["test"],
						Index: ExecNoCopyout,
						Props: CallProps{4, false, 0},
					},
					{
						Meta:  target.SyscallMap["test"],
						Index: ExecNoCopyout,
						Props: CallProps{0, true, 10},
					},
				},
			},
		},
		{
			`test$res3(&(0x7f0000000010)=<r0=>0x0)
test$res1(r0)
`,
			[]any{
				callID("test$res3"), ExecNoCopyout, 1, execArgAddr64, 0x10,
				execInstrCopyout, 0, 0x10, 4,
				callID("test$res1"), ExecNoCopyout, 1, execArgResult, 4, 0, 0, 0, 0xffff,
				execInstrEOF,
			},
			&ExecProg{
				Calls: []ExecCall{
					{
						Meta:  target.SyscallMap["test$res3"],
						Index: ExecNoCopyout,
						Args: []ExecArg{
							ExecArgConst{
								Value: dataOffset + 0x10,
								Size:  8,
							},
						},
						Copyout: []ExecCopyout{
							{
								Index: 0,
								Addr:  dataOffset + 0x10,
								Size:  4,
							},
						},
					},
					{
						Meta:  target.SyscallMap["test$res1"],
						Index: ExecNoCopyout,
						Args: []ExecArg{
							ExecArgResult{
								Size:    4,
								Index:   0,
								Default: 0xffff,
							},
						},
					},
				},
				Vars: []uint64{0xffff},
			},
		},
	}

	for i, test := range tests {
		t.Run(fmt.Sprintf("%v:%v", i, test.prog), func(t *testing.T) {
			p, err := target.Deserialize([]byte(test.prog), Strict)
			if err != nil {
				t.Fatalf("failed to deserialize prog %v: %v", i, err)
			}
			data, err := p.SerializeForExec()
			if err != nil {
				t.Fatalf("failed to serialize: %v", err)
			}
			want := binary.AppendVarint(nil, int64(len(p.Calls)))
			for _, e := range test.serialized {
				switch elem := e.(type) {
				case uint64:
					want = binary.AppendVarint(want, int64(elem))
				case int:
					want = binary.AppendVarint(want, int64(elem))
				case []byte:
					want = append(want, elem...)
				default:
					t.Fatalf("unexpected elem type %T %#v", e, e)
				}
			}
			if !bytes.Equal(data, want) {
				t.Logf("want: %v", test.serialized)
				t.Logf("got:  %q", data)
				t.Fatalf("mismatch")
			}
			decoded, err := target.DeserializeExec(data, nil)
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

func TestSerializeForExecOverflow(t *testing.T) {
	target := initTargetTest(t, "test", "64")
	type Test struct {
		name     string
		overflow bool
		gen      func(w *bytes.Buffer)
	}
	tests := []Test{
		{
			name:     "few-resources",
			overflow: false,
			gen: func(w *bytes.Buffer) {
				for i := 0; i < execMaxCommands-10; i++ {
					fmt.Fprintf(w, "r%v = test$res0()\ntest$res1(r%v)\n", i, i)
				}
			},
		},
		{
			name:     "overflow-resources",
			overflow: true,
			gen: func(w *bytes.Buffer) {
				for i := 0; i < execMaxCommands+1; i++ {
					fmt.Fprintf(w, "r%v = test$res0()\ntest$res1(r%v)\n", i, i)
				}
			},
		},
		{
			name:     "no-verflow-buffer",
			overflow: false,
			gen: func(w *bytes.Buffer) {
				fmt.Fprintf(w, "r0 = test$res0()\n")
				for i := 0; i < 58e3; i++ {
					fmt.Fprintf(w, "test$res1(r0)\n")
				}
			},
		},
		{
			name:     "overflow-buffer",
			overflow: true,
			gen: func(w *bytes.Buffer) {
				fmt.Fprintf(w, "r0 = test$res0()\n")
				for i := 0; i < 4e5; i++ {
					fmt.Fprintf(w, "test$res1(r0)\n")
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			data := new(bytes.Buffer)
			test.gen(data)
			p, err := target.Deserialize(data.Bytes(), Strict)
			if err != nil {
				t.Fatal(err)
			}
			_, err = p.SerializeForExec()
			if test.overflow && err == nil {
				t.Fatalf("want overflow but got no error")
			}
			if !test.overflow && err != nil {
				t.Fatalf("want no overflow but got %v", err)
			}
		})
	}
}
