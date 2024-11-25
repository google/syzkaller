// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io/fs"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/google/syzkaller/pkg/ast"
	"github.com/google/syzkaller/pkg/compiler"
	"github.com/google/syzkaller/pkg/ifaceprobe"
	"github.com/google/syzkaller/pkg/mgrconfig"
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/subsystem"
	_ "github.com/google/syzkaller/pkg/subsystem/lists"
	"github.com/google/syzkaller/pkg/tool"
	"github.com/google/syzkaller/sys/targets"
)

var (
	autoFile = filepath.FromSlash("sys/linux/auto.txt")
	target   = targets.Get(targets.Linux, targets.AMD64)
)

func main() {
	var (
		flagConfig       = flag.String("config", "", "manager config file")
		flagBinary       = flag.String("binary", "syz-declextract", "path to syz-declextract binary")
		flagCacheExtract = flag.Bool("cache-extract", false, "use cached extract results if present"+
			" (cached in manager.workdir/declextract.cache)")
		flagCacheProbe = flag.Bool("cache-probe", false, "use cached probe results if present"+
			" (cached in manager.workdir/interfaces.json)")
	)
	defer tool.Init()()
	cfg, err := mgrconfig.LoadFile(*flagConfig)
	if err != nil {
		tool.Failf("failed to load manager config: %v", err)
	}

	var probeInfo *ifaceprobe.Info
	probeDone := make(chan error)
	go func() {
		var err error
		probeInfo, err = probe(cfg, *flagConfig, *flagCacheProbe)
		if err != nil {
			tool.Failf("kernel probing failed: %v", err)
		}
		close(probeDone)
	}()

	compilationDatabase := filepath.Join(cfg.KernelObj, "compile_commands.json")
	cmds, err := loadCompileCommands(compilationDatabase)
	if err != nil {
		tool.Failf("failed to load compile commands: %v", err)
	}

	ctx := &context{
		cfg:                 cfg,
		clangTool:           *flagBinary,
		compilationDatabase: compilationDatabase,
		compileCommands:     cmds,
		extractor:           subsystem.MakeExtractor(subsystem.GetList(target.OS)),
		syscallNameMap:      readSyscallMap(cfg.KernelSrc),
		interfaces:          make(map[string]Interface),
		fdNames:             make(map[string]int),
		ioctlNames:          make(map[string]int),
	}

	outputs := make(chan *output, len(cmds))
	files := make(chan string, len(cmds))
	for w := 0; w < runtime.NumCPU(); w++ {
		go ctx.worker(outputs, files, *flagCacheExtract)
	}

	for _, cmd := range cmds {
		files <- cmd.File
	}
	close(files)

	for range cmds {
		out := <-outputs
		if out == nil {
			continue
		}
		file, err := filepath.Rel(cfg.KernelSrc, out.file)
		if err != nil {
			tool.Fail(err)
		}
		if out.err != nil {
			tool.Failf("%v: %v", file, out.err)
		}
		parse := ast.Parse(out.output, "", nil)
		if parse == nil {
			tool.Failf("%v: parsing error:\n%s", file, out.output)
		}
		ctx.appendNodes(parse.Nodes, file)
	}
	ctx.finishDescriptions()

	<-probeDone
	ctx.parseProbeInfo(probeInfo)

	slices.SortFunc(ctx.fops, func(a, b *OutputFops) int {
		return strings.Compare(a.String(), b.String())
	})
	ctx.fops = slices.CompactFunc(ctx.fops, func(a, b *OutputFops) bool {
		return a.String() == b.String()
	})
	for _, fops := range ctx.fops {
		ctx.createFops(fops)
	}

	desc := &ast.Description{
		Nodes: ctx.nodes,
	}
	writeDescriptions(desc)
	// In order to remove unused bits of the descriptions, we need to write them out first,
	// and then parse all descriptions back b/c auto descriptions use some types defined
	// by manual descriptions (compiler.CollectUnused requires complete descriptions).
	removeUnused(desc)
	writeDescriptions(desc)

	ifaces := ctx.finishInterfaces()
	ifacesData := serializeInterfaces(ifaces)
	if err := osutil.WriteFile(autoFile+".info", ifacesData); err != nil {
		tool.Fail(err)
	}
}

type context struct {
	cfg                 *mgrconfig.Config
	clangTool           string
	compilationDatabase string
	compileCommands     []compileCommand
	extractor           *subsystem.Extractor
	syscallNameMap      map[string][]string
	interfaces          map[string]Interface
	nodes               []ast.Node
	fops                []*OutputFops
	probeFuncToFiles    map[string]map[string]bool
	fdNames             map[string]int
	ioctlNames          map[string]int
}

// OutputTop represents json output of the clang tool.
type OutputTop struct {
	Fops *OutputFops
}

// OutputFops describes one file_operations variable.
type OutputFops struct {
	// Names of callback functions.
	Open  string
	Read  string
	Write string
	Mmap  string
	Ioctl string
	Cmds  []OutputIoctlCmd // set of ioctl commands
}

type OutputIoctlCmd struct {
	Name string // literal name of the command (e.g. KCOV_REMOTE_ENABLE
	Type string // inferred syzlang type (e.g. ptr[in, int32])
}

func (fops *OutputFops) String() string {
	w := new(bytes.Buffer)
	fmt.Fprintf(w, "fops:")
	writefop := func(name, fn string) {
		if fn != "" {
			fmt.Fprintf(w, " %v:%v", name, fn)
		}
	}
	writefop("open", fops.Open)
	writefop("read", fops.Read)
	writefop("write", fops.Write)
	writefop("mmap", fops.Mmap)
	writefop("ioctl", fops.Ioctl)
	return w.String()
}

func probe(cfg *mgrconfig.Config, cfgFile string, cache bool) (*ifaceprobe.Info, error) {
	if cache {
		info, err := readProbeResult(cfg)
		if err == nil {
			return info, nil
		}
	}
	_, err := osutil.RunCmd(30*time.Minute, "", filepath.Join(cfg.Syzkaller, "bin", "syz-manager"),
		"-config", cfgFile, "-mode", "iface-probe")
	if err != nil {
		return nil, err
	}
	return readProbeResult(cfg)
}

func readProbeResult(cfg *mgrconfig.Config) (*ifaceprobe.Info, error) {
	data, err := os.ReadFile(filepath.Join(cfg.Workdir, "interfaces.json"))
	if err != nil {
		return nil, err
	}
	info := new(ifaceprobe.Info)
	if err := json.Unmarshal(data, info); err != nil {
		return nil, fmt.Errorf("failed to unmarshal interfaces.json: %w", err)
	}
	return info, nil
}

func (ctx *context) parseProbeInfo(info *ifaceprobe.Info) {
	pcToFunc := make(map[uint64]string)
	for _, pc := range info.PCs {
		pcToFunc[pc.PC] = pc.Func
	}
	ctx.probeFuncToFiles = make(map[string]map[string]bool)
	for _, file := range info.Files {
		for _, pc := range file.Cover {
			fn := pcToFunc[pc]
			files := ctx.probeFuncToFiles[fn]
			if files == nil {
				files = make(map[string]bool)
				ctx.probeFuncToFiles[fn] = files
			}
			files[file.Name] = true
		}
	}
}

func (ctx *context) createFops(fops *OutputFops) {
	// TODO: also emit interface entry for the fops.
	if fops.Read == "" && fops.Write == "" && fops.Mmap == "" && fops.Ioctl == "" {
		return
	}
	name, files := ctx.mapFopsToFiles(fops)
	if len(files) == 0 {
		fmt.Printf("%v: %v is not mapped to any file\n", name, fops)
		return
	}
	fmt.Printf("%v: %v mapped to %v\n", name, fops, files[:min(10, len(files))])

	// Some fops are mapped to too many files, usually these have generic callbacks
	// like simple_attr_read+simple_attr_write. Compiler restricts number of strings to 2000.
	// TODO: emit multiple open calls to cover all files.
	files = files[:min(len(files), 1000)]
	w := new(bytes.Buffer)
	fmt.Fprintf(w, "\n# %v\n", fops)
	fmt.Fprintf(w, "resource fd_%v[fd]\n", name)
	fileFlags := fmt.Sprintf("\"%s\"", files[0])
	if len(files) > 1 {
		fileFlags = fmt.Sprintf("%v_files", name)
		fmt.Fprintf(w, "%v = ", fileFlags)
		for i, file := range files {
			if i != 0 {
				fmt.Fprintf(w, ", ")
			}
			fmt.Fprintf(w, "\"%v\"", file)
		}
		fmt.Fprintf(w, "\n")
	}
	fmt.Fprintf(w, "openat$%v(fd const[AT_FDCWD], file ptr[in, string[%v]],"+
		" flags flags[open_flags], mode const[0]) fd_%v (automatic)\n",
		name, fileFlags, name)
	if fops.Read != "" {
		fmt.Fprintf(w, "read$%v(fd fd_%v, buf ptr[out, array[int8]],"+
			" len bytesize[buf]) (automatic)\n", name, name)
	}
	if fops.Write != "" {
		fmt.Fprintf(w, "write$%v(fd fd_%v, buf ptr[in, array[int8]],"+
			" len bytesize[buf]) (automatic)\n", name, name)
	}
	if fops.Mmap != "" {
		fmt.Fprintf(w, "mmap$%v(addr vma, len len[addr], prot flags[mmap_prot],"+
			" flags flags[mmap_flags], fd fd_%v, offset fileoff) (automatic)\n", name, name)
	}
	if fops.Ioctl != "" {
		if len(fops.Cmds) == 0 {
			fmt.Fprintf(w, "ioctl$%v(fd fd_%v, cmd intptr,"+
				" arg ptr[in, array[int8]]) (automatic)\n", name, name)
		} else {
			for _, cmd := range fops.Cmds {
				suffix := ""
				ctx.ioctlNames[cmd.Name]++
				if ctx.ioctlNames[cmd.Name] != 1 {
					suffix += fmt.Sprint(ctx.ioctlNames[cmd.Name])
				}
				fmt.Fprintf(w, "ioctl$auto_%v%v(fd fd_%v, cmd const[%v], arg %v) (automatic)\n",
					cmd.Name, suffix, name, cmd.Name, cmd.Type)
			}
		}
	}
	fmt.Fprintf(w, "\n")

	parsed := ast.Parse(w.Bytes(), "", nil)
	if parsed == nil {
		panic(fmt.Sprintf("parsing failed:\n%s", w.Bytes()))
	}
	ctx.nodes = append(ctx.nodes, parsed.Nodes...)
	ctx.nodes = append(ctx.nodes, &ast.NewLine{})
}

func (ctx *context) mapFopsToFiles(fops *OutputFops) (string, []string) {
	first := true
	var files map[string]bool
	var unique map[string]int
	for _, fn := range []string{fops.Open, fops.Read, fops.Write, fops.Mmap, fops.Ioctl} {
		if fn == "" {
			continue
		}
		files1 := ctx.probeFuncToFiles[fn]
		var unique1 map[string]int
		if fn != "seq_read" && !strings.HasPrefix(fn, "generic_") &&
			!strings.HasPrefix(fn, "simple_") {
			unique1 = make(map[string]int)
			for i, part := range strings.Split(fn, "_") {
				switch part {
				case "read", "write", "ioctl", "mmap", "open", "fops":
					continue
				}
				unique1[part] = i
			}
			if unique == nil {
				unique = unique1
			} else {
				for part := range unique {
					if _, ok := unique1[part]; !ok {
						delete(unique, part)
					}
				}
			}
		}
		if first {
			first = false
			files = files1
			continue
		} else {
			for file := range files {
				if !files1[file] {
					delete(files, file)
				}
			}
		}
	}
	type namePart struct {
		name string
		idx  int
	}
	var parts []namePart
	for part, idx := range unique {
		parts = append(parts, namePart{part, idx})
	}
	slices.SortFunc(parts, func(a, b namePart) int {
		return a.idx - b.idx
	})
	name := "auto"
	for _, part := range parts {
		name += "_" + part.name
	}
	if len(files) == 0 {
		return name, nil
	}
	ctx.fdNames[name]++
	if ctx.fdNames[name] != 1 || len(parts) == 0 {
		name += fmt.Sprint(ctx.fdNames[name])
	}
	var sortedFiles []string
	for file := range files {
		sortedFiles = append(sortedFiles, file)
	}
	slices.Sort(sortedFiles)
	return name, sortedFiles
}

type compileCommand struct {
	Command   string
	Directory string
	File      string
}

func loadCompileCommands(file string) ([]compileCommand, error) {
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var cmds []compileCommand
	if err := json.Unmarshal(data, &cmds); err != nil {
		return nil, err
	}
	// Remove commands that don't relate to the kernel build
	// (probably some host tools, etc).
	cmds = slices.DeleteFunc(cmds, func(cmd compileCommand) bool {
		return !strings.HasSuffix(cmd.File, ".c") ||
			// Files compiled with gcc are not a part of the kernel
			// (assuming compile commands were generated with make CC=clang).
			// They are probably a part of some host tool.
			strings.HasPrefix(cmd.Command, "gcc") ||
			// KBUILD should add this define all kernel files.
			!strings.Contains(cmd.Command, "-DKBUILD_BASENAME")
	})
	// Shuffle the order to detect any non-determinism caused by the order early.
	// The result should be the same regardless.
	rand.New(rand.NewSource(time.Now().UnixNano())).Shuffle(len(cmds), func(i, j int) {
		cmds[i], cmds[j] = cmds[j], cmds[i]
	})
	return cmds, nil
}

type output struct {
	file   string
	output []byte
	err    error
}

type Interface struct {
	Type               string
	Name               string
	Files              []string
	Func               string
	Access             string
	Subsystems         []string
	ManualDescriptions bool
	AutoDescriptions   bool

	identifyingConst string
}

func (iface *Interface) ID() string {
	return fmt.Sprintf("%v/%v", iface.Type, iface.Name)
}

func serializeInterfaces(ifaces []Interface) []byte {
	w := new(bytes.Buffer)
	for _, iface := range ifaces {
		fmt.Fprintf(w, "%v\t%v\tfunc:%v\taccess:%v\tmanual_desc:%v\tauto_desc:%v",
			iface.Type, iface.Name, iface.Func, iface.Access,
			iface.ManualDescriptions, iface.AutoDescriptions)
		for _, file := range iface.Files {
			fmt.Fprintf(w, "\tfile:%v", file)
		}
		for _, subsys := range iface.Subsystems {
			fmt.Fprintf(w, "\tsubsystem:%v", subsys)
		}
		fmt.Fprintf(w, "\n")
	}
	return w.Bytes()
}

func (ctx *context) finishInterfaces() []Interface {
	var interfaces []Interface
	for _, iface := range ctx.interfaces {
		slices.Sort(iface.Files)
		iface.Files = slices.Compact(iface.Files)
		var crashes []*subsystem.Crash
		for _, file := range iface.Files {
			crashes = append(crashes, &subsystem.Crash{GuiltyPath: file})
		}
		for _, s := range ctx.extractor.Extract(crashes) {
			iface.Subsystems = append(iface.Subsystems, s.Name)
		}
		slices.Sort(iface.Subsystems)
		if iface.Access == "" {
			iface.Access = "unknown"
		}
		interfaces = append(interfaces, iface)
	}
	slices.SortFunc(interfaces, func(a, b Interface) int {
		return strings.Compare(a.ID(), b.ID())
	})
	checkDescriptionPresence(interfaces, autoFile)
	return interfaces
}

func (ctx *context) mergeInterface(iface Interface) {
	prev, ok := ctx.interfaces[iface.ID()]
	if ok {
		if iface.identifyingConst != prev.identifyingConst {
			tool.Failf("interface %v has different identifying consts: %v vs %v",
				iface.ID(), iface.identifyingConst, prev.identifyingConst)
		}
		iface.Files = append(iface.Files, prev.Files...)
	}
	ctx.interfaces[iface.ID()] = iface
}

func checkDescriptionPresence(interfaces []Interface, autoFile string) {
	desc := ast.ParseGlob(filepath.Join("sys", target.OS, "*.txt"), nil)
	if desc == nil {
		tool.Failf("failed to parse descriptions")
	}
	consts := compiler.ExtractConsts(desc, target, nil)
	auto := make(map[string]bool)
	manual := make(map[string]bool)
	for file, desc := range consts {
		for _, c := range desc.Consts {
			if file == autoFile {
				auto[c.Name] = true
			} else {
				manual[c.Name] = true
			}
		}
	}
	for i := range interfaces {
		iface := &interfaces[i]
		if auto[iface.identifyingConst] {
			iface.AutoDescriptions = true
		}
		if manual[iface.identifyingConst] {
			iface.ManualDescriptions = true
		}
	}
}

func writeDescriptions(desc *ast.Description) {
	// New lines are added in the parsing step. This is why we need to Format (serialize the description),
	// Parse, then Format again.
	output := ast.Format(ast.Parse(ast.Format(desc), "", ast.LoggingHandler))
	if err := osutil.WriteFile(autoFile, output); err != nil {
		tool.Fail(err)
	}
}

func (ctx *context) finishDescriptions() {
	slices.SortFunc(ctx.nodes, func(a, b ast.Node) int {
		return strings.Compare(ast.SerializeNode(a), ast.SerializeNode(b))
	})
	ctx.nodes = slices.CompactFunc(ctx.nodes, func(a, b ast.Node) bool {
		return ast.SerializeNode(a) == ast.SerializeNode(b)
	})
	slices.SortStableFunc(ctx.nodes, func(a, b ast.Node) int {
		return getTypeOrder(a) - getTypeOrder(b)
	})

	prevCall, prevCallIndex := "", 0
	for _, node := range ctx.nodes {
		switch n := node.(type) {
		case *ast.Call:
			if n.Name.Name == prevCall {
				n.Name.Name += strconv.Itoa(prevCallIndex)
				prevCallIndex++
			} else {
				prevCall = n.Name.Name
				prevCallIndex = 0
			}
		}
	}

	// These additional includes must be at the top (added after sorting), because other kernel headers
	// are broken and won't compile without these additional ones included first.
	header := `# Code generated by syz-declextract. DO NOT EDIT.

include <include/vdso/bits.h>
include <include/linux/types.h>
`
	desc := ast.Parse([]byte(header), "", nil)
	ctx.nodes = append(desc.Nodes, ctx.nodes...)
}

func removeUnused(desc *ast.Description) {
	all := ast.ParseGlob(filepath.Join("sys", target.OS, "*.txt"), nil)
	if all == nil {
		tool.Failf("failed to parse descriptions")
	}
	unusedNodes, err := compiler.CollectUnused(all, target, nil)
	if err != nil {
		tool.Failf("failed to typecheck descriptions: %v", err)
	}
	unused := make(map[string]bool)
	for _, n := range unusedNodes {
		if pos, typ, name := n.Info(); pos.File == autoFile {
			unused[fmt.Sprintf("%v/%v", typ, name)] = true
		}
	}
	desc.Nodes = slices.DeleteFunc(desc.Nodes, func(n ast.Node) bool {
		_, typ, name := n.Info()
		return unused[fmt.Sprintf("%v/%v", typ, name)]
	})
}

func (ctx *context) worker(outputs chan *output, files chan string, cache bool) {
	for file := range files {
		cacheFile := filepath.Join(ctx.cfg.Workdir, "declextract.cache",
			strings.TrimPrefix(strings.TrimPrefix(filepath.Clean(file),
				ctx.cfg.KernelSrc), ctx.cfg.KernelObj))
		if cache {
			out, err := os.ReadFile(cacheFile)
			if err == nil {
				outputs <- &output{file, out, nil}
				continue
			}
		}
		// Suppress warning since we may build the tool on a different clang
		// version that produces more warnings.
		out, err := exec.Command(ctx.clangTool, "-p", ctx.compilationDatabase, file, "--extra-arg=-w").Output()
		var exitErr *exec.ExitError
		if err != nil && errors.As(err, &exitErr) && len(exitErr.Stderr) != 0 {
			err = fmt.Errorf("%s", exitErr.Stderr)
		}
		if err == nil {
			osutil.MkdirAll(filepath.Dir(cacheFile))
			osutil.WriteFile(cacheFile, out)
		}
		outputs <- &output{file, out, err}
	}
}

func (ctx *context) renameSyscall(syscall *ast.Call) []ast.Node {
	names := ctx.syscallNameMap[syscall.CallName]
	if len(names) == 0 {
		// Syscall has no record in the tables for the architectures we support.
		return nil
	}
	variant := strings.TrimPrefix(syscall.Name.Name, syscall.CallName)
	if variant == "" {
		variant = "$auto"
	}
	var renamed []ast.Node
	for _, name := range names {
		newCall := syscall.Clone().(*ast.Call)
		newCall.Name.Name = name + variant
		newCall.CallName = name // Not required	but avoids mistakenly treating CallName as the part before the $.
		renamed = append(renamed, newCall)
	}

	return renamed
}

func readSyscallMap(sourceDir string) map[string][]string {
	// Parse arch/*/*.tbl files that map functions defined with SYSCALL_DEFINE macros to actual syscall names.
	// Lines in the files look as follows:
	//	288      common  accept4                 sys_accept4
	// Total mapping is many-to-many, so we give preference to x86 arch, then to 64-bit syscalls,
	// and then just order arches by name to have deterministic result.
	type desc struct {
		fn      string
		arch    string
		is64bit bool
	}
	syscalls := make(map[string][]desc)
	for _, arch := range targets.List[target.OS] {
		filepath.Walk(filepath.Join(sourceDir, "arch", arch.KernelHeaderArch),
			func(path string, info fs.FileInfo, err error) error {
				if err != nil || !strings.HasSuffix(path, ".tbl") {
					return err
				}
				f, err := os.Open(path)
				if err != nil {
					tool.Fail(err)
				}
				defer f.Close()
				for s := bufio.NewScanner(f); s.Scan(); {
					fields := strings.Fields(s.Text())
					if len(fields) < 4 || fields[0] == "#" {
						continue
					}
					group := fields[1]
					syscall := fields[2]
					fn := strings.TrimPrefix(fields[3], "sys_")
					if strings.HasPrefix(syscall, "unused") || fn == "-" ||
						// Powerpc spu group defines some syscalls (utimesat)
						// that are not present on any of our arches.
						group == "spu" ||
						// llseek does not exist, it comes from:
						//	arch/arm64/tools/syscall_64.tbl -> scripts/syscall.tbl
						//	62  32      llseek                          sys_llseek
						// So scripts/syscall.tbl is pulled for 64-bit arch, but the syscall
						// is defined only for 32-bit arch in that file.
						syscall == "llseek" ||
						// Don't want to test it (see issue 5308).
						syscall == "reboot" {
						continue
					}
					syscalls[syscall] = append(syscalls[syscall], desc{
						fn:      fn,
						arch:    arch.VMArch,
						is64bit: group == "common" || strings.Contains(group, "64"),
					})
				}
				return nil
			})
	}

	rename := map[string][]string{
		"syz_genetlink_get_family_id": {"syz_genetlink_get_family_id"},
	}
	for syscall, descs := range syscalls {
		slices.SortFunc(descs, func(a, b desc) int {
			if (a.arch == target.Arch) != (b.arch == target.Arch) {
				if a.arch == target.Arch {
					return -1
				}
				return 1
			}
			if a.is64bit != b.is64bit {
				if a.is64bit {
					return -1
				}
				return 1
			}
			return strings.Compare(a.arch, b.arch)
		})
		fn := descs[0].fn
		rename[fn] = append(rename[fn], syscall)
	}
	return rename
}

func (ctx *context) appendNodes(nodes []ast.Node, file string) {
	for _, node := range nodes {
		switch node := node.(type) {
		case *ast.Call:
			// Some syscalls have different names and entry points and thus need to be renamed.
			// e.g. SYSCALL_DEFINE1(setuid16, old_uid_t, uid) is referred to in the .tbl file with setuid.
			ctx.nodes = append(ctx.nodes, ctx.renameSyscall(node)...)
		case *ast.Include:
			if file, err := filepath.Rel(ctx.cfg.KernelSrc, filepath.Join(ctx.cfg.KernelObj, node.File.Value)); err == nil {
				node.File.Value = file
			}
			if replace := includeReplaces[node.File.Value]; replace != "" {
				node.File.Value = replace
			}
			ctx.nodes = append(ctx.nodes, node)
		case *ast.Comment:
			switch {
			case strings.HasPrefix(node.Text, "INTERFACE:"):
				fields := strings.Fields(node.Text)
				if len(fields) != 6 {
					tool.Failf("%q has wrong number of fields", node.Text)
				}
				for i := range fields {
					if fields[i] == "-" {
						fields[i] = ""
					}
				}
				iface := Interface{
					Type:             fields[1],
					Name:             fields[2],
					Files:            []string{file},
					identifyingConst: fields[3],
					Func:             fields[4],
					Access:           fields[5],
				}
				if iface.Type == "SYSCALL" {
					for _, name := range ctx.syscallNameMap[iface.Name] {
						iface.Name = name
						iface.identifyingConst = "__NR_" + name
						ctx.mergeInterface(iface)
					}
				} else {
					ctx.mergeInterface(iface)
				}
			case strings.HasPrefix(node.Text, "JSON:"):
				top := new(OutputTop)
				if err := json.Unmarshal([]byte(node.Text[5:]), top); err != nil {
					tool.Failf("failed to unmarshal json %q: %v", node.Text, err)
				}
				if top.Fops != nil {
					ctx.fops = append(ctx.fops, top.Fops)
				}
			default:
				ctx.nodes = append(ctx.nodes, node)
			}
		default:
			ctx.nodes = append(ctx.nodes, node)
		}
	}
}

// Replace these includes in the tool output.
var includeReplaces = map[string]string{
	// Arches may use some includes from asm-generic and some from arch/arm.
	// If the arch used for extract used asm-generic for a header,
	// other arches may need arch/asm version of the header. So switch to
	// a more generic file name that should resolve correctly for all arches.
	"include/uapi/asm-generic/ioctls.h":  "asm/ioctls.h",
	"include/uapi/asm-generic/sockios.h": "asm/sockios.h",
}

func getTypeOrder(a ast.Node) int {
	switch a.(type) {
	case *ast.Comment:
		return 0
	case *ast.Include:
		return 1
	case *ast.Define:
		return 2
	case *ast.IntFlags:
		return 3
	case *ast.Resource:
		return 4
	case *ast.TypeDef:
		return 5
	case *ast.Call:
		return 6
	case *ast.Struct:
		return 7
	case *ast.NewLine:
		return 8
	default:
		panic(fmt.Sprintf("unhandled type %T", a))
	}
}
