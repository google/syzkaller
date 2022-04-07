// Copyright 2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package symbolizer

import (
	"bufio"
	"fmt"
	"os"
	"reflect"
	"strconv"
	"testing"
)

func TestParse(t *testing.T) {
	addresses := []struct {
		pc     uint64
		resp   string
		frames []Frame
	}{
		{
			0xffffffff8180a42e,
			"0xffffffff8180a42e\n" +
				"__asan_report_load2_noabort\n" +
				"mm/kasan/report.c:320\n",
			[]Frame{
				{
					PC:     0xffffffff8180a42e,
					Func:   "__asan_report_load2_noabort",
					File:   "mm/kasan/report.c",
					Line:   320,
					Inline: false,
				},
			},
		},
		{
			0xffffffff8180a42d,
			"0xffffffff8180a42d\n" +
				"kasan_report\n" +
				"mm/kasan/report.c:301\n" +
				"__asan_report_load2_noabort\n" +
				"mm/kasan/report.c:320\n",
			[]Frame{
				{
					PC:     0xffffffff8180a42d,
					Func:   "kasan_report",
					File:   "mm/kasan/report.c",
					Line:   301,
					Inline: true,
				},
				{
					PC:     0xffffffff8180a42d,
					Func:   "__asan_report_load2_noabort",
					File:   "mm/kasan/report.c",
					Line:   320,
					Inline: false,
				},
			},
		},
		{
			0xffffffff82fdbe0b,
			"0xffffffff82fdbe0b\n" +
				"fbcon_invert_region\n" +
				"drivers/video/console/fbcon.c:2750\n",
			[]Frame{
				{
					PC:     0xffffffff82fdbe0b,
					Func:   "fbcon_invert_region",
					File:   "drivers/video/console/fbcon.c",
					Line:   2750,
					Inline: false,
				},
			},
		},
		{
			0x123124,
			"0x0000000000123124\n" +
				"??\n" +
				"??:0\n",
			nil,
		},
		{
			0xffffffffffffffff,
			"0xffffffffffffffff\n" +
				"??\n" +
				"??:0\n",
			nil,
		},
		{
			0xffffffff81a2aff9,
			"0xffffffff81a2aff9\n" +
				"devpts_get_priv\n" +
				"fs/devpts/inode.c:588 (discriminator 3)\n",
			[]Frame{
				{
					PC:     0xffffffff81a2aff9,
					Func:   "devpts_get_priv",
					File:   "fs/devpts/inode.c",
					Line:   588,
					Inline: false,
				},
			},
		},
	}

	// Stub addr2line.
	inputr, inputw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer inputr.Close()
	defer inputw.Close()
	outputr, outputw, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer outputr.Close()
	done := make(chan error)
	go func() {
		s := bufio.NewScanner(inputr)
	loop:
		for s.Scan() {
			pc, err := strconv.ParseUint(s.Text(), 0, 64)
			if err != nil {
				outputw.Close()
				done <- fmt.Errorf("got unexpected pc: %v", s.Text())
				return
			}
			for _, addr := range addresses {
				if pc == addr.pc {
					outputw.Write([]byte(addr.resp))
					continue loop
				}
			}
			outputw.Close()
			done <- fmt.Errorf("got unexpected pc: 0x%x", pc)
			return
		}
		outputw.Write([]byte("DONE\n"))
		outputw.Close()
		close(done)
	}()
	defer func() {
		inputw.Close()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}()

	// First, symbolize all PCs one-by-one.
	input := bufio.NewWriter(inputw)
	scanner := bufio.NewScanner(outputr)
	var allPCs []uint64
	var allFrames []Frame
	for _, addr := range addresses {
		frames, err := symbolize(input, scanner, []uint64{addr.pc})
		if err != nil {
			t.Fatalf("got error: %v", err)
		}
		if !reflect.DeepEqual(addr.frames, frames) {
			t.Fatalf("want frames:\n%+v\ngot:\n%+v\n", addr.frames, frames)
		}
		allPCs = append(allPCs, addr.pc)
		allFrames = append(allFrames, frames...)
	}

	// Symbolize PCs in 2 groups.
	for i := 0; i <= len(addresses); i++ {
		frames, err := symbolize(input, scanner, allPCs[:i])
		if err != nil {
			t.Fatalf("got error: %v", err)
		}
		frames2, err := symbolize(input, scanner, allPCs[i:])
		if err != nil {
			t.Fatalf("got error: %v", err)
		}
		frames = append(frames, frames2...)
		if !reflect.DeepEqual(allFrames, frames) {
			t.Fatalf("want frames:\n%+v\ngot:\n%+v\n", allFrames, frames)
		}
	}

	// Symbolize a huge pile of PCs (test for pipe overflows).
	lots := make([]uint64, 1e4)
	for i := range lots {
		lots[i] = addresses[0].pc
	}
	frames, err := symbolize(input, scanner, lots)
	if err != nil {
		t.Fatalf("got error: %v", err)
	}
	if want := len(lots) * len(addresses[0].frames); want != len(frames) {
		t.Fatalf("want %v frames, got %v", want, len(frames))
	}
}
