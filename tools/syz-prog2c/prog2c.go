// Copyright 2015 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	"github.com/google/syzkaller/pkg/csource"
	"github.com/google/syzkaller/pkg/kfuzztest"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/prog"
	_ "github.com/google/syzkaller/sys"
)

var (
	flagOS         = flag.String("os", runtime.GOOS, "target os")
	flagArch       = flag.String("arch", runtime.GOARCH, "target arch")
	flagBuild      = flag.Bool("build", false, "also build the generated program")
	flagThreaded   = flag.Bool("threaded", false, "create threaded program")
	flagRepeat     = flag.Int("repeat", 1, "repeat program that many times (<=0 - infinitely)")
	flagProcs      = flag.Int("procs", 1, "number of parallel processes")
	flagSlowdown   = flag.Int("slowdown", 1, "execution slowdown caused by emulation/instrumentation")
	flagSandbox    = flag.String("sandbox", "", "sandbox to use (none, setuid, namespace, android)")
	flagSandboxArg = flag.Int("sandbox_arg", 0, "argument for executor to customize its behavior")
	flagProg       = flag.String("prog", "", "file with program to convert (required)")
	flagHandleSegv = flag.Bool("segv", false, "catch and ignore SIGSEGV")
	flagUseTmpDir  = flag.Bool("tmpdir", false, "create a temporary dir and execute inside it")
	flagTrace      = flag.Bool("trace", false, "trace syscall results")
	flagStrict     = flag.Bool("strict", false, "parse input program in strict mode")
	flagLeak       = flag.Bool("leak", false, "do leak checking")
	flagEnable     = flag.String("enable", "none", "enable only listed additional features")
	flagDisable    = flag.String("disable", "none", "enable all additional features except listed")
	flagVmlinux    = flag.String("vmlinux", "", "path to vmlinux binary (required for dynamically discovered calls")
	flagFormat     = flag.Bool("format", true, "use clang-format to format c code")
	flagCSB        = flag.Bool("csb", false, "generate CSB test header instead of c file")
	flagNumNop     = flag.Int("num_nop", 0, "number of NOPs per operation")
	flagCFile      = flag.String("cfile", "", "output c file instead of stdout")
	flagNumInvoc   = flag.Int("num_invoc", 10000, "max number of invocations per syscall")
)

type BMConfigApps struct {
	Name       string `json:"name"`
	Operations []int  `json:"operations"`
}

type BMConfig struct {
	Multi_value_fields_plot string         `json:"multi_value_fields_plot"`
	Duration                int            `json:"duration"`
	Repeat                  int            `json:"repeat"`
	Applications            []BMConfigApps `json:"applications"`
}

func sanitizePath(path []byte) ([]byte, string) {
	ret := path
	f := string(ret[:])
	if f[0] == '/' {
		ret = []byte("." + f)
	}
	f = string(ret[:])
	upDir := "../"
	numUp := strings.Count(f, upDir)
	if numUp > 0 {
		ret = []byte(strings.Repeat("a/", numUp) + f)
	}
	f = string(ret[:])

	directory_path := filepath.Dir(f)
	if f[len(f)-1] == '/' {
		directory_path = f
	}

	if byte(directory_path[len(directory_path)-1]) == 0x00 {
		panic("null character at the end of directory_path")
	}

	return ret, directory_path
}

func sanitizePathArg(call *prog.Call, argnum int) string {
	// Sanitize arg path to be relative
	a := call.Args[argnum].(*prog.PointerArg)
	d := a.Res.(*prog.DataArg)
	newData, subdirPath := sanitizePath(d.Data())
	d.SetData(newData)

	return subdirPath
}

func sanitizeOpenAt(call *prog.Call, subdirs map[string](bool), filemap map[uint64](string)) (map[string](bool), map[uint64](string)) {
	// get result fd to track paths and filesizes
	r := call.Ret
	for r.Res != nil {
		r = r.Res
	}
	resNum := r.Val

	// Sanitize arg path to be relative
	subdirPath := sanitizePathArg(call, 1)
	subdirs[subdirPath] = true

	a1 := call.Args[1].(*prog.PointerArg)
	// path argument
	d1 := a1.Res.(*prog.DataArg)
	data := d1.Data()
	for len(data) > 1 && data[len(data)-1] == 0x00 {
		data = data[:len(data)-1]
	}
	d1_str := string(data)

	if len(d1_str) > 0 && byte(d1_str[len(d1_str)-1]) == 0x00 {
		panic("null character at the end of directory_path")
	}

	_, ok := filemap[resNum]
	if !ok {
		filemap[resNum] = d1_str
	}

	// adds O_CREAT if O_DIRECTORY is not specified (include O_TMPFILE)
	a2 := call.Args[2].(*prog.ConstArg)
	if (a2.Val & syscall.O_DIRECTORY) != syscall.O_DIRECTORY {
		a2.Val |= syscall.O_CREAT
	}

	// if it wants to open a directory, put the complete path into the list of created directories
	if (a2.Val & syscall.O_DIRECTORY) == syscall.O_DIRECTORY {
		subdirs[d1_str] = true
	}

	// removes O_EXCL
	a2.Val &= ^uint64(syscall.O_EXCL)

	// removes O_DIRECT
	a2.Val &= ^uint64(syscall.O_DIRECT)

	// d2 := a2.Val

	// sets permissions on file create to 0777
	a3 := call.Args[3].(*prog.ConstArg)
	a3.Val = syscall.S_IRWXU | syscall.S_IRWXG | syscall.S_IRWXO

	return subdirs, filemap
}

func sanitizePwrite64(call *prog.Call, filesizes map[uint64](uint64)) map[uint64](uint64) {
	// Retrieve resource accessed
	a0 := call.Args[0].(*prog.ResultArg)
	for a0.Res != nil {
		a0 = a0.Res
	}
	resNum := a0.Val

	// get the count
	a2 := call.Args[2].(*prog.ConstArg)

	// get the offset
	a3 := call.Args[3].(*prog.ConstArg)

	// store is offset + count is above current max
	max, ok := filesizes[resNum]
	if !ok || a2.Val+a3.Val > max {
		filesizes[resNum] = a2.Val + a3.Val
	}

	return filesizes
}

func sanitizePread64(call *prog.Call, filesizes map[uint64](uint64)) map[uint64](uint64) {
	// Retrieve resource accessed
	a0 := call.Args[0].(*prog.ResultArg)
	for a0.Res != nil {
		a0 = a0.Res
	}
	resNum := a0.Val

	// get the count
	a2 := call.Args[2].(*prog.ConstArg)

	// get the offset
	a3 := call.Args[3].(*prog.ConstArg)

	// store is offset + count is above current max
	max, ok := filesizes[resNum]
	if !ok || a2.Val+a3.Val > max {
		filesizes[resNum] = a2.Val + a3.Val
	}

	return filesizes
}

func sanitizeFallocate(call *prog.Call, filesizes map[uint64](uint64)) map[uint64](uint64) {
	// Retrieve resource accessed
	a0 := call.Args[0].(*prog.ResultArg)
	for a0.Res != nil {
		a0 = a0.Res
	}
	resNum := a0.Val

	// get the offset
	a2 := call.Args[2].(*prog.ConstArg)

	// get the size
	a3 := call.Args[3].(*prog.ConstArg)

	// store is offset + count is above current max
	max, ok := filesizes[resNum]
	if !ok || a2.Val+a3.Val > max {
		filesizes[resNum] = a2.Val + a3.Val
	}

	return filesizes
}

func sanitizeReadlinkat(call *prog.Call, subdirs map[string](bool)) map[string](bool) {
	subdirPath := sanitizePathArg(call, 1)
	subdirs[subdirPath] = true

	// treat all readlinkat paths as directory...
	a1 := call.Args[1].(*prog.PointerArg)
	// path argument
	d1 := a1.Res.(*prog.DataArg)
	data := d1.Data()
	for data[len(data)-1] == 0x00 && len(data) > 1 {
		data = data[:len(data)-1]
	}
	d1_str := string(data)
	subdirs[d1_str] = true

	// check if buffer size is 0 (bug in syzkaller?)
	a3 := call.Args[3].(*prog.ConstArg)
	if a3.Val == 0 {
		// syzkaller seams to allocate a buffer of size 0x80 bytes for it in memory
		a3.Val = 0x80
	}

	return subdirs
}

func sanitizeBind(call *prog.Call, subdirs map[string](bool)) map[string](bool) {
	//TODO: Add support for bind
	return subdirs
}

// returns (sanitzed program,map with all sub to be accessed directories,map with resultnum/filesize)
func sanitizeProgram(p *prog.Prog, progName string) (*prog.Prog, map[string](bool), map[uint64](uint64), map[uint64](string)) {
	subdirs := make(map[string](bool))
	filesizes := make(map[uint64](uint64))
	filemap := make(map[uint64](string))
	for _, call := range p.Calls {
		switch call.Meta.Name {
		case "openat":
			subdirs, filemap = sanitizeOpenAt(call, subdirs, filemap)
		case "pwrite64":
			filesizes = sanitizePwrite64(call, filesizes)
		case "pread64":
			filesizes = sanitizePread64(call, filesizes)
		case "faccessat":
			subdirPath := sanitizePathArg(call, 1)
			subdirs[subdirPath] = true
		case "faccessat2":
			subdirPath := sanitizePathArg(call, 1)
			subdirs[subdirPath] = true
		case "newfstatat":
			subdirPath := sanitizePathArg(call, 1)
			subdirs[subdirPath] = true
		case "readlinkat":
			subdirs = sanitizeReadlinkat(call, subdirs)
		case "fallocate":
			filesizes = sanitizeFallocate(call, filesizes)
		case "bind":
			sanitizeBind(call, subdirs)
		case "unlinkat":
			subdirPath := sanitizePathArg(call, 1)
			subdirs[subdirPath] = true
		case "mknodat":
			subdirPath := sanitizePathArg(call, 1)
			subdirs[subdirPath] = true
		case "fchownat":
			subdirPath := sanitizePathArg(call, 1)
			subdirs[subdirPath] = true
		case "fchmodat":
			subdirPath := sanitizePathArg(call, 1)
			subdirs[subdirPath] = true
		}
	}

	// add empty size for files that have no found max size (just create them)
	for key := range filemap {
		_, ok := filesizes[key]
		if !ok {
			filesizes[key] = 0
		}
	}

	// remove sizes for files that do not appear as paths
	for key := range filesizes {
		_, ok := filemap[key]
		if !ok {
			delete(filesizes, key)
		}
	}

	if len(filesizes) != len(filemap) {
		fmt.Fprintf(os.Stderr, "Differing filenames and filesizes length!\n Check %s\n", progName)
	}

	return p, subdirs, filesizes, filemap
}

// returns limited program with regard to having a maximum number of *flagNumInvoc invocations per syscall
func limitProgram(p *prog.Prog) *prog.Prog {
	pLim := p.Clone()
	pLim.Calls = nil
	invocations := make(map[string](int))
	for _, call := range p.Calls {
		callName := call.Meta.Name
		_, ok := invocations[callName]
		if !ok {
			invocations[callName] = 1
		} else {
			invocations[callName]++
		}

		if invocations[callName] <= *flagNumInvoc {
			pLim.Calls = append(pLim.Calls, call)
		}
	}
	return pLim
}

func main() {
	flag.Usage = func() {
		flag.PrintDefaults()
		csource.PrintAvailableFeaturesFlags()
	}
	flag.Parse()
	if *flagProg == "" {
		flag.Usage()
		os.Exit(1)
	}
	progName := filepath.Base(*flagProg)

	features, err := csource.ParseFeaturesFlags(*flagEnable, *flagDisable, false)
	if err != nil {
		log.Fatalf("%v", err)
	}
	target, err := prog.GetTarget(*flagOS, *flagArch)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
	if *flagVmlinux != "" {
		_, err = kfuzztest.ActivateKFuzzTargets(target, *flagVmlinux)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
			os.Exit(1)
		}
	}
	data, err := os.ReadFile(*flagProg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read prog file: %v\n", err)
		os.Exit(1)
	}
	mode := prog.NonStrict
	if *flagStrict {
		mode = prog.Strict
	}
	p, err := target.Deserialize(data, mode)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to deserialize the program: %v\n", err)
		os.Exit(1)
	}

	// limit size of program
	pLim := limitProgram(p)
	p = pLim

	// sanitize program
	pSan, subDirs, filesize, filemap := sanitizeProgram(p, progName)
	p = pSan

	opts := csource.Options{
		Threaded:      *flagThreaded,
		Repeat:        *flagRepeat != 1,
		RepeatTimes:   *flagRepeat,
		Procs:         *flagProcs,
		Slowdown:      *flagSlowdown,
		Sandbox:       *flagSandbox,
		SandboxArg:    *flagSandboxArg,
		Leak:          *flagLeak,
		NetInjection:  features["tun"].Enabled,
		NetDevices:    features["net_dev"].Enabled,
		NetReset:      features["net_reset"].Enabled,
		Cgroups:       features["cgroups"].Enabled,
		BinfmtMisc:    features["binfmt_misc"].Enabled,
		CloseFDs:      features["close_fds"].Enabled,
		KCSAN:         features["kcsan"].Enabled,
		DevlinkPCI:    features["devlink_pci"].Enabled,
		NicVF:         features["nic_vf"].Enabled,
		USB:           features["usb"].Enabled,
		VhciInjection: features["vhci"].Enabled,
		Wifi:          features["wifi"].Enabled,
		IEEE802154:    features["ieee802154"].Enabled,
		Sysctl:        features["sysctl"].Enabled,
		Swap:          features["swap"].Enabled,
		UseTmpDir:     *flagUseTmpDir,
		HandleSegv:    *flagHandleSegv,
		Trace:         *flagTrace,
		CSB:           *flagCSB,
		NumNop:        *flagNumNop,
		SubDirs:       subDirs,
		FileSizes:     filesize,
		FileNames:     filemap,
		CallComments:  true,
	}

	src, err := csource.Write(p, opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to generate C source: %v\n", err)
		os.Exit(1)
	}

	if *flagFormat {
		if formatted, err := csource.Format(src); err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
		} else {
			src = formatted
		}
	}

	// store information about the program being minimized or a thread representation in the generated c file
	/*
	 * This header represents a complete thread as extracted from the strace log.
	 */
	/*
	 * This header represents a minimized program extracted from one thread of the strace log.
	 */

	if *flagCFile != "" {
		var outFilePath string
		var fileBaseWithoutExt string
		var fileIdx int
		fileExt := filepath.Ext(*flagCFile)

		// generate path without extension
		if len(fileExt) > 0 {
			fileBaseWithoutExt = strings.TrimSuffix(*flagCFile, fileExt)
		} else {
			fileBaseWithoutExt = *flagCFile
		}

		fileIdx = 0
		outFilePath = fileBaseWithoutExt + "_" + strconv.Itoa(fileIdx) + fileExt

		_, err := os.Stat(outFilePath)
		for !errors.Is(err, os.ErrNotExist) {
			fileIdx++
			outFilePath = fileBaseWithoutExt + "_" + strconv.Itoa(fileIdx) + fileExt
			_, err = os.Stat(outFilePath)
		}
		if err := osutil.WriteFile(outFilePath, src); err != nil {
			log.Fatalf("failed to output file: %v", err)
		}
		log.Printf("Stored program %s", outFilePath)

	} else {
		os.Stdout.Write(src)
	}

	if !*flagBuild {
		return
	}

	bin, err := csource.Build(target, src)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to build C source: %v\n", err)
		os.Exit(1)
	}
	os.Remove(bin)
	fmt.Fprintf(os.Stderr, "binary build OK\n")
}
