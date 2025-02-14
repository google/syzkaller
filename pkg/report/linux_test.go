// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package report

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/symbolizer"
	"github.com/google/syzkaller/pkg/vminfo"
	"github.com/google/syzkaller/sys/targets"
)

func TestLinuxIgnores(t *testing.T) {
	cfg := &mgrconfig.Config{
		Derived: mgrconfig.Derived{
			TargetOS:   targets.Linux,
			TargetArch: targets.AMD64,
		},
	}
	reporter, err := NewReporter(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Ignores = []string{"BUG: bug3"}
	reporter1, err := NewReporter(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Ignores = []string{"BUG: bug3", "BUG: bug1"}
	reporter2, err := NewReporter(cfg)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Ignores = []string{"BUG: bug3", "BUG: bug1", "BUG: bug2"}
	reporter3, err := NewReporter(cfg)
	if err != nil {
		t.Fatal(err)
	}

	const log = `
[    0.000000] BUG: bug1
[    0.000000] BUG: bug2
	`
	if !reporter.ContainsCrash([]byte(log)) {
		t.Fatalf("no crash")
	}
	if rep := reporter.Parse([]byte(log)); rep.Title != "BUG: bug1" {
		t.Fatalf("want `BUG: bug1`, found `%v`", rep.Title)
	}

	if !reporter1.ContainsCrash([]byte(log)) {
		t.Fatalf("no crash")
	}
	if rep := reporter1.Parse([]byte(log)); rep.Title != "BUG: bug1" {
		t.Fatalf("want `BUG: bug1`, found `%v`", rep.Title)
	}

	if !reporter2.ContainsCrash([]byte(log)) {
		t.Fatalf("no crash")
	}
	if rep := reporter2.Parse([]byte(log)); rep.Title != "BUG: bug2" {
		t.Fatalf("want `BUG: bug2`, found `%v`", rep.Title)
	}

	if reporter3.ContainsCrash([]byte(log)) {
		t.Fatalf("found crash, should be ignored")
	}
	if rep := reporter3.Parse([]byte(log)); rep != nil {
		t.Fatalf("found `%v`, should be ignored", rep.Title)
	}
}

func TestLinuxSymbolizeLine(t *testing.T) {
	tests := []struct {
		line   string
		result string
	}{
		// Normal symbolization.
		{
			"[ 2713.153531]  [<ffffffff82d1b1d9>] foo+0x101/0x185\n",
			"[ 2713.153531]  [<ffffffff82d1b1d9>] foo+0x101/0x185 foo.c:555\n",
		},
		{
			"RIP: 0010:[<ffffffff8188c0e6>]  [<ffffffff8188c0e6>]  foo+0x101/0x185\n",
			"RIP: 0010:[<ffffffff8188c0e6>]  [<ffffffff8188c0e6>]  foo+0x101/0x185 foo.c:550\n",
		},
		// Strip "./" file prefix.
		{
			"[ 2713.153531]  [<ffffffff82d1b1d9>] foo+0x111/0x185\n",
			"[ 2713.153531]  [<ffffffff82d1b1d9>] foo+0x111/0x185 foo.h:111\n",
		},
		// Needs symbolization, but symbolizer returns nothing.
		{
			"[ 2713.153531]  [<ffffffff82d1b1d9>] foo+0x121/0x185\n",
			"[ 2713.153531]  [<ffffffff82d1b1d9>] foo+0x121/0x185\n",
		},
		// Needs symbolization, but symbolizer returns error.
		{
			"[ 2713.153531]  [<ffffffff82d1b1d9>] foo+0x131/0x185\n",
			"[ 2713.153531]  [<ffffffff82d1b1d9>] foo+0x131/0x185\n",
		},
		// Needs symbolization, but symbol is missing.
		{
			"[ 2713.153531]  [<ffffffff82d1b1d9>] bar+0x131/0x185\n",
			"[ 2713.153531]  [<ffffffff82d1b1d9>] bar+0x131/0x185\n",
		},
		// Bad offset.
		{
			"[ 2713.153531]  [<ffffffff82d1b1d9>] bar+0xffffffffffffffffffff/0x185\n",
			"[ 2713.153531]  [<ffffffff82d1b1d9>] bar+0xffffffffffffffffffff/0x185\n",
		},
		// Should not be symbolized.
		{
			"WARNING: CPU: 2 PID: 2636 at ipc/shm.c:162 foo+0x101/0x185\n",
			"WARNING: CPU: 2 PID: 2636 at ipc/shm.c:162 foo+0x101/0x185 foo.c:555\n",
		},
		// Tricky function name.
		{
			"    [<ffffffff84e5bea0>] do_ipv6_setsockopt.isra.7.part.3+0x101/0x2830 \n",
			"    [<ffffffff84e5bea0>] do_ipv6_setsockopt.isra.7.part.3+0x101/0x2830 net.c:111 \n",
		},
		// Old KASAN frame format (with tab).
		{
			"[   50.419727] 	baz+0x101/0x200\n",
			"[   50.419727] 	baz+0x101/0x200 baz.c:100\n",
		},
		// Inlined frames.
		{
			"    [<ffffffff84e5bea0>] foo+0x141/0x185\n",
			"    [<ffffffff84e5bea0>] inlined1 net.c:111 [inline]\n" +
				"    [<ffffffff84e5bea0>] inlined2 mm.c:222 [inline]\n" +
				"    [<ffffffff84e5bea0>] foo+0x141/0x185 kasan.c:333\n",
		},
		// Several symbols with the same name.
		{
			"[<ffffffff82d1b1d9>] baz+0x101/0x200\n",
			"[<ffffffff82d1b1d9>] baz+0x101/0x200 baz.c:100\n",
		},
		// Frame format with module+offset.
		{
			"[   50.419727][ T3822] baz+0x101/0x200 [beep]\n",
			"[   50.419727][ T3822] baz+0x101/0x200 baz.c:100 [beep]\n",
		},
		// Frame format with module+offset and stracktrace_build_id.
		{
			"[   50.419727][ T3822] baz+0x101/0x200 [beep b31b29679ab712c360bddd861f655ab24898b4db]\n",
			"[   50.419727][ T3822] baz+0x101/0x200 baz.c:100 [beep]\n",
		},

		// Frame format with module+offset for invalid module.
		{
			"[   50.419727][ T3822] baz+0x101/0x200 [invalid_module]\n",
			"[   50.419727][ T3822] baz+0x101/0x200 [invalid_module]\n",
		},
		// Frame format with module+offset for missing symbol.
		{
			"[   50.419727][ T3822] missing_symbol+0x101/0x200 [beep]\n",
			"[   50.419727][ T3822] missing_symbol+0x101/0x200 [beep]\n",
		},
		// Frame format with module+offset for invalid offset.
		{
			"[   50.419727][ T3822] baz+0x300/0x200 [beep]\n",
			"[   50.419727][ T3822] baz+0x300/0x200 [beep]\n",
		},
	}
	symbols := map[string]map[string][]symbolizer.Symbol{
		"": {
			"foo": {
				{Addr: 0x1000000, Size: 0x190},
			},
			"do_ipv6_setsockopt.isra.7.part.3": {
				{Addr: 0x2000000, Size: 0x2830},
			},
			"baz": {
				{Addr: 0x3000000, Size: 0x100},
				{Addr: 0x4000000, Size: 0x200},
				{Addr: 0x5000000, Size: 0x300},
			},
		},
		"beep": {
			"baz": {
				{Addr: 0x4000000, Size: 0x200},
			},
		},
	}
	symb := func(bin string, pc uint64) ([]symbolizer.Frame, error) {
		if bin == "beep" {
			switch pc {
			case 0x4000100:
				return []symbolizer.Frame{
					{
						File: "/linux/baz.c",
						Line: 100,
					},
				}, nil
			default:
				return nil, fmt.Errorf("unknown pc 0x%x", pc)
			}
		}
		if bin != "vmlinux" {
			return nil, fmt.Errorf("unknown pc 0x%x", pc)
		}
		switch pc {
		case 0x1000100:
			return []symbolizer.Frame{
				{
					File: "/linux/foo.c",
					Line: 555,
				},
			}, nil
		case 0x1000101:
			return []symbolizer.Frame{
				{
					File: "/linux/foo.c",
					Line: 550,
				},
			}, nil
		case 0x1000110:
			return []symbolizer.Frame{
				{
					File: "/linux/./foo.h",
					Line: 111,
				},
			}, nil
		case 0x1000120:
			return nil, nil
		case 0x1000130:
			return nil, fmt.Errorf("unknown pc 0x%x", pc)
		case 0x2000100:
			return []symbolizer.Frame{
				{
					File: "/linux/net.c",
					Line: 111,
				},
			}, nil
		case 0x1000140:
			return []symbolizer.Frame{
				{
					Func:   "inlined1",
					File:   "/linux/net.c",
					Line:   111,
					Inline: true,
				},
				{
					Func:   "inlined2",
					File:   "/linux/mm.c",
					Line:   222,
					Inline: true,
				},
				{
					Func:   "noninlined3",
					File:   "/linux/kasan.c",
					Line:   333,
					Inline: false,
				},
			}, nil
		case 0x4000100:
			return []symbolizer.Frame{
				{
					File: "/linux/baz.c",
					Line: 100,
				},
			}, nil
		default:
			return nil, fmt.Errorf("unknown pc 0x%x", pc)
		}
	}
	modules := []*vminfo.KernelModule{
		{
			Name: "",
			Path: "vmlinux",
		},
		{
			Name: "beep",
			Path: "beep",
		},
	}

	cfg := &config{
		kernelObj:     "/linux",
		kernelModules: modules,
	}
	ctx := &linux{
		config:  cfg,
		vmlinux: "vmlinux",
		symbols: symbols,
	}
	for i, test := range tests {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			result := symbolizeLine(symb, ctx, []byte(test.line))
			if test.result != string(result) {
				t.Errorf("want %q\n\t     get %q", test.result, string(result))
			}
		})
	}
}

func prepareLinuxReporter(t *testing.T, arch string) (*Reporter, *linux) {
	cfg := &mgrconfig.Config{
		Derived: mgrconfig.Derived{
			TargetOS:   targets.Linux,
			TargetArch: arch,
			SysTarget:  targets.Get(targets.Linux, arch),
		},
	}
	reporter, err := NewReporter(cfg)
	if err != nil {
		t.Errorf("failed to create a reporter instance for %#v: %v", arch, err)
	}
	return reporter, reporter.impl.(*linux)
}

func TestParseLinuxOpcodes(t *testing.T) {
	type opcodeTest struct {
		arch   string
		input  string
		output *parsedOpcodes
	}

	tests := []opcodeTest{
		// LE tests.
		{
			arch:  targets.AMD64,
			input: "31 c0 <e8> f5 bf f7 ff",
			output: &parsedOpcodes{
				rawBytes: []byte{0x31, 0xc0, 0xe8, 0xf5, 0xbf, 0xf7, 0xff},
				offset:   2,
			},
		},
		{
			arch:  targets.AMD64,
			input: "c031 <f5e8> f7bf fff7 00ff",
			output: &parsedOpcodes{
				rawBytes: []byte{0x31, 0xc0, 0xe8, 0xf5, 0xbf, 0xf7, 0xf7, 0xff, 0xff, 0x00},
				offset:   2,
			},
		},
		{
			arch:  targets.AMD64,
			input: "(33221100) 77665544",
			output: &parsedOpcodes{
				rawBytes: []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77},
				offset:   0,
			},
		},
		// BE tests.
		{
			arch:  targets.S390x,
			input: "31 c0 <e8> f5 bf f7 ff",
			output: &parsedOpcodes{
				rawBytes: []byte{0x31, 0xc0, 0xe8, 0xf5, 0xbf, 0xf7, 0xff},
				offset:   2,
			},
		},
		{
			arch:  targets.S390x,
			input: "31c0 <e8f5> bff5 f7ff ff00",
			output: &parsedOpcodes{
				rawBytes: []byte{0x31, 0xc0, 0xe8, 0xf5, 0xbf, 0xf5, 0xf7, 0xff, 0xff, 0x00},
				offset:   2,
			},
		},
		{
			arch:  targets.S390x,
			input: "<00112233> 44556677",
			output: &parsedOpcodes{
				rawBytes: []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77},
				offset:   0,
			},
		},
		// ARM Thumb tests.
		{
			arch:  targets.ARM,
			input: "0011 (2233) 4455",
			output: &parsedOpcodes{
				rawBytes:       []byte{0x11, 0x00, 0x33, 0x22, 0x55, 0x44},
				decompileFlags: FlagForceArmThumbMode,
				offset:         2,
			},
		},
		{
			arch:  targets.ARM,
			input: "(33221100) 77665544",
			output: &parsedOpcodes{
				rawBytes: []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77},
				offset:   0,
			},
		},
		// Bad input tests.
		{
			arch:   targets.AMD64,
			input:  "00 11 22 33",
			output: nil,
		},
		{
			arch:   targets.AMD64,
			input:  "aa bb <cc> zz",
			output: nil,
		},
		{
			arch:   targets.AMD64,
			input:  "<00> 11 22 <33>",
			output: nil,
		},
		{
			arch:   targets.AMD64,
			input:  "aa  <bb>",
			output: nil,
		},
		{
			arch:   targets.AMD64,
			input:  "001122 334455",
			output: nil,
		},
		{
			arch:   targets.AMD64,
			input:  "0011223344556677",
			output: nil,
		},
	}

	for idx, test := range tests {
		t.Run(fmt.Sprintf("%s/%v", test.arch, idx), func(t *testing.T) {
			t.Parallel()
			_, linuxReporter := prepareLinuxReporter(t, test.arch)
			ret, err := linuxReporter.parseOpcodes(test.input)
			if test.output == nil && err == nil {
				t.Errorf("expected an error on input %#v", test)
			} else if test.output != nil && err != nil {
				t.Errorf("unexpected error %v on input %#v", err, test.input)
			} else if test.output != nil && !reflect.DeepEqual(ret, *test.output) {
				t.Errorf("expected: %#v, got: %#v", test.output, ret)
			}
		})
	}
}

func TestDisassemblyInReports(t *testing.T) {
	if runtime.GOOS != targets.Linux {
		t.Skipf("the test is meant to be run only under Linux")
	}

	archPath := filepath.Join("testdata", "linux", "decompile")
	subFolders, err := os.ReadDir(archPath)
	if err != nil {
		t.Fatalf("disassembly reports failed: %v", err)
	}

	for _, obj := range subFolders {
		if !obj.IsDir() {
			continue
		}
		reporter, linuxReporter := prepareLinuxReporter(t, obj.Name())
		if linuxReporter.target.BrokenCompiler != "" {
			t.Skip("skipping the test due to broken cross-compiler:\n" + linuxReporter.target.BrokenCompiler)
		}

		testPath := filepath.Join(archPath, obj.Name())
		testFiles, err := os.ReadDir(testPath)
		if err != nil {
			t.Fatalf("failed to list tests for %v: %v", obj.Name(), err)
		}

		for _, file := range testFiles {
			if !strings.HasSuffix(file.Name(), ".in") {
				continue
			}
			filePath := filepath.Join(testPath, strings.TrimSuffix(file.Name(), ".in"))
			t.Run(obj.Name()+"/"+file.Name(), func(t *testing.T) {
				testDisassembly(t, reporter, linuxReporter, filePath)
			})
		}
	}
}

func testDisassembly(t *testing.T, reporter *Reporter, linuxReporter *linux, testFilePrefix string) {
	t.Parallel()

	input, err := os.ReadFile(testFilePrefix + ".in")
	if err != nil {
		t.Fatalf("failed to read input file: %v", err)
	}

	report := reporter.Parse(input)
	if report == nil {
		t.Fatalf("no bug report was found")
	}

	result := linuxReporter.decompileOpcodes(input, report)
	if *flagUpdate {
		osutil.WriteFile(testFilePrefix+".out", result)
	}

	output, err := os.ReadFile(testFilePrefix + ".out")
	if err != nil {
		t.Fatalf("failed to read output file: %v", err)
	}

	if !bytes.Equal(output, result) {
		t.Fatalf("expected:\n%s\ngot:\n%s", output, result)
	}
}
