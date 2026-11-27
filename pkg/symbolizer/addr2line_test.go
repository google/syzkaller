// Copyright 2016 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package symbolizer

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"testing"

	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/sys/targets"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParse(t *testing.T) {
	addresses := []struct {
		pc     uint64
		resp   string
		frames []Frame
	}{
		{
			0xffffffff8180a42e,
			`0xffffffff8180a42e
__asan_report_load2_noabort
mm/kasan/report.c:320
`,
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
			`0xffffffff8180a42d
kasan_report
mm/kasan/report.c:301
__asan_report_load2_noabort
mm/kasan/report.c:320
`,
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
			`0xffffffff82fdbe0b
fbcon_invert_region
drivers/video/console/fbcon.c:2750
`,
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
			0xffffffff82fdbe1b,
			`0xffffffff82fdbe1b
fbcon_invert_region
drivers/video/console/fbcon.c:0
`,
			[]Frame{
				{
					PC:     0xffffffff82fdbe1b,
					Func:   "fbcon_invert_region",
					File:   "drivers/video/console/fbcon.c",
					Line:   -1,
					Inline: false,
				},
			},
		},
		{
			0x123124,
			`0x0000000000123124
??
??:0
`,
			nil,
		},
		{
			0xffffffffffffffff,
			`0xffffffffffffffff
??
??:0
`,
			nil,
		},
		{
			0xffffffff81a2aff9,
			`0xffffffff81a2aff9
devpts_get_priv
fs/devpts/inode.c:588 (discriminator 3)
`,
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
		{
			0xffffffff81001200,
			`0xffffffff81001200
do_ipv6_setsockopt.isra.7.part.3
net/ipv6/ipv6_sockglue.c:396
`,
			[]Frame{
				{
					PC:     0xffffffff81001200,
					Func:   "do_ipv6_setsockopt",
					File:   "net/ipv6/ipv6_sockglue.c",
					Line:   396,
					Inline: false,
				},
			},
		},
		{
			0xffffffff81001235,
			`0xffffffff81001235
___slab_alloc.constprop.78
mm/slub.c:3066
`,
			[]Frame{
				{
					PC:     0xffffffff81001235,
					Func:   "___slab_alloc",
					File:   "mm/slub.c",
					Line:   3066,
					Inline: false,
				},
			},
		},
		{
			0xffffffff81001239,
			`0xffffffff81001239
kasan_report.part.2
mm/kasan/report.c:552
___slab_alloc.constprop.78
mm/slub.c:3066
`,
			[]Frame{
				{
					PC:     0xffffffff81001239,
					Func:   "kasan_report",
					File:   "mm/kasan/report.c",
					Line:   552,
					Inline: true,
				},
				{
					PC:     0xffffffff81001239,
					Func:   "___slab_alloc",
					File:   "mm/slub.c",
					Line:   3066,
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
	var interner Interner
	var allPCs []uint64
	var allFrames []Frame
	for _, addr := range addresses {
		frames, err := symbolize(&interner, input, scanner, []uint64{addr.pc})
		if err != nil {
			t.Fatalf("got error: %v", err)
		}
		if !reflect.DeepEqual(addr.frames, frames) {
			t.Fatalf("want frames:\n%+v\ngot:\n%+v", addr.frames, frames)
		}
		allPCs = append(allPCs, addr.pc)
		allFrames = append(allFrames, frames...)
	}

	// Symbolize PCs in 2 groups.
	for i := 0; i <= len(addresses); i++ {
		frames, err := symbolize(&interner, input, scanner, allPCs[:i])
		if err != nil {
			t.Fatalf("got error: %v", err)
		}
		frames2, err := symbolize(&interner, input, scanner, allPCs[i:])
		if err != nil {
			t.Fatalf("got error: %v", err)
		}
		frames = append(frames, frames2...)
		if !reflect.DeepEqual(allFrames, frames) {
			t.Fatalf("want frames:\n%+v\ngot:\n%+v", allFrames, frames)
		}
	}

	// Symbolize a huge pile of PCs (test for pipe overflows).
	lots := make([]uint64, 1e4)
	for i := range lots {
		lots[i] = addresses[0].pc
	}
	frames, err := symbolize(&interner, input, scanner, lots)
	if err != nil {
		t.Fatalf("got error: %v", err)
	}
	if want := len(lots) * len(addresses[0].frames); want != len(frames) {
		t.Fatalf("want %v frames, got %v", want, len(frames))
	}
}

func TestCleanFuncName(t *testing.T) {
	for _, test := range []struct {
		name, want string
	}{
		{"do_ip_setsockopt.isra.12", "do_ip_setsockopt"},
		{"print_circular_bug.isra.36.cold.53", "print_circular_bug"},
		{"___slab_alloc.constprop.78", "___slab_alloc"},
		{"foo.cold.12345", "foo"},
		{"foo.part.0", "foo"},
		{"__list_add_valid.cold", "__list_add_valid"},
		{"foo.isra.0.cold", "foo"},
		// A name that consists of a suffix only is left as is.
		{".cold", ".cold"},
		{"LZ4_decompress_safe_partial", "LZ4_decompress_safe_partial"},
		{"__sta_info_destroy_part1", "__sta_info_destroy_part1"},
	} {
		assert.Equal(t, test.want, cleanFuncName(test.name), "cleanFuncName(%q)", test.name)
	}
}

func TestSymbolizeSandbox(t *testing.T) {
	osutil.RequireSandbox(t)
	symb := Make(targets.Get(targets.Linux, targets.AMD64))
	t.Cleanup(symb.Close)

	_, err := symb.Symbolize("testdata/nm.test.out", 0x400507)
	require.NoError(t, err)

	secretBin := filepath.Join(osutil.SandboxTempDir(t), "secret.bin")
	require.NoError(t, osutil.CopyFile("testdata/nm.test.out", secretBin))
	require.NoError(t, os.Chmod(secretBin, 0600))
	_, err = symb.Symbolize(secretBin, 0x400507)
	require.Error(t, err)
}
