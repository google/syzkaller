// Copyright 2024 syzkaller project authors. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bufio"
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
	"github.com/google/syzkaller/pkg/osutil"
	"github.com/google/syzkaller/pkg/subsystem"
	_ "github.com/google/syzkaller/pkg/subsystem/lists"
	"github.com/google/syzkaller/pkg/tool"
	"github.com/google/syzkaller/sys/targets"
)

func main() {
	var (
		binary    = flag.String("binary", "syz-declextract", "path to binary")
		outFile   = flag.String("output", "sys/linux/auto.txt", "output file")
		sourceDir = flag.String("sourcedir", "", "kernel source directory")
		buildDir  = flag.String("builddir", "", "kernel build directory (defaults to source directory)")
	)
	defer tool.Init()()
	if *sourceDir == "" {
		tool.Failf("path to kernel source directory is required")
	}
	if *buildDir == "" {
		*buildDir = *sourceDir
	}
	*sourceDir = filepath.Clean(osutil.Abs(*sourceDir))
	*buildDir = filepath.Clean(osutil.Abs(*buildDir))

	compilationDatabase := filepath.Join(*buildDir, "compile_commands.json")
	fileData, err := os.ReadFile(compilationDatabase)
	if err != nil {
		tool.Fail(err)
	}

	extractor := subsystem.MakeExtractor(subsystem.GetList(targets.Linux))

	var cmds []compileCommand
	if err := json.Unmarshal(fileData, &cmds); err != nil {
		tool.Fail(err)
	}
	// Shuffle the order detect any non-determinism caused by the order early.
	// The result should be the same regardless.
	rand.New(rand.NewSource(time.Now().UnixNano())).Shuffle(len(cmds), func(i, j int) {
		cmds[i], cmds[j] = cmds[j], cmds[i]
	})

	outputs := make(chan *output, len(cmds))
	files := make(chan string, len(cmds))
	for w := 0; w < runtime.NumCPU(); w++ {
		go worker(outputs, files, *binary, compilationDatabase)
	}

	for _, cmd := range cmds {
		// Files compiled with gcc are not a part of the kernel
		// (assuming compile commands were generated with make CC=clang).
		// They are probably a part of some host tool.
		if !strings.HasSuffix(cmd.File, ".c") || strings.HasPrefix(cmd.Command, "gcc") {
			outputs <- nil
			continue
		}
		files <- cmd.File
	}
	close(files)

	syscallNames := readSyscallMap(*sourceDir)

	var nodes []ast.Node
	var interfaces []Interface
	eh := ast.LoggingHandler
	for range cmds {
		out := <-outputs
		if out == nil {
			continue
		}
		file, err := filepath.Rel(*sourceDir, out.file)
		if err != nil {
			tool.Fail(err)
		}
		if out.err != nil {
			tool.Failf("%v: %v", file, out.err)
		}
		parse := ast.Parse(out.output, "", eh)
		if parse == nil {
			tool.Failf("%v: parsing error:\n%s", file, out.output)
		}
		appendNodes(&nodes, &interfaces, parse.Nodes, syscallNames, *sourceDir, *buildDir, file, extractor)
	}

	// New lines are added in the parsing step. This is why we need to Format (serialize the description),
	// Parse, then Format again.
	desc := finishDescriptions(nodes)
	output := ast.Format(ast.Parse(ast.Format(desc), "", ast.LoggingHandler))
	if err := osutil.WriteFile(*outFile, output); err != nil {
		tool.Fail(err)
	}

	checkDescriptionPresence(interfaces, *outFile)
	slices.SortFunc(interfaces, func(a, b Interface) int {
		if x := strings.Compare(a.Type, b.Type); x != 0 {
			return x
		}
		return strings.Compare(a.Name, b.Name)
	})
	interfaces = slices.CompactFunc(interfaces, func(a, b Interface) bool {
		return a.Type == b.Type && a.Name == b.Name
	})
	data, err := json.MarshalIndent(interfaces, "", "\t")
	if err != nil {
		tool.Failf("failed to marshal interfaces: %v", err)
	}
	if err := osutil.WriteFile(*outFile+".json", data); err != nil {
		tool.Fail(err)
	}
}

type compileCommand struct {
	Command   string
	Directory string
	File      string
}

type output struct {
	file   string
	output []byte
	err    error
}

type Interface struct {
	Type               string   `json:"type"`
	Name               string   `json:"name"`
	Files              []string `json:"files"`
	Subsystems         []string `json:"subsystems"`
	ManualDescriptions bool     `json:"has_manual_descriptions"`
	AutoDescriptions   bool     `json:"has_auto_descriptions"`

	identifyingConst string
}

func checkDescriptionPresence(interfaces []Interface, autoFile string) {
	desc := ast.ParseGlob(filepath.Join("sys", targets.Linux, "*.txt"), nil)
	if desc == nil {
		tool.Failf("failed to parse descriptions")
	}
	consts := compiler.ExtractConsts(desc, targets.List[targets.Linux][targets.AMD64], nil)
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

const sendmsg = "sendmsg"

func finishDescriptions(nodes []ast.Node) *ast.Description {
	slices.SortFunc(nodes, func(a, b ast.Node) int {
		return strings.Compare(ast.SerializeNode(a), ast.SerializeNode(b))
	})
	nodes = slices.CompactFunc(nodes, func(a, b ast.Node) bool {
		return ast.SerializeNode(a) == ast.SerializeNode(b)
	})
	slices.SortStableFunc(nodes, func(a, b ast.Node) int {
		return getTypeOrder(a) - getTypeOrder(b)
	})

	var syscalls []*ast.Call
	var structs []*ast.Struct
	for _, node := range nodes {
		switch node := node.(type) {
		case *ast.Call:
			syscalls = append(syscalls, node)
		case *ast.Struct:
			// Special case for unsued struct. TODO: handle unused structs.
			if node.Name.Name == "old_utimbuf32$auto_record" {
				continue
			}
			structs = append(structs, node)
		case *ast.Include, *ast.TypeDef, *ast.Resource, *ast.IntFlags, *ast.NewLine, *ast.Comment:
			continue
		default:
			_, typ, _ := node.Info()
			tool.Failf("unhandled Node type: %v", typ)
		}
	}
	// NOTE: The -2 at the end is to account for one unused struct and one newline
	nodes = nodes[:len(nodes)-len(structs)-len(syscalls)-2]

	sendmsgNo := 0
	// Some commands are executed for multiple policies. Ensure that they don't get deleted by the following compact call.
	for i := 1; i < len(syscalls); i++ {
		if syscalls[i].CallName == sendmsg && syscalls[i].Name.Name == syscalls[i-1].Name.Name {
			syscalls[i].Name.Name += strconv.Itoa(sendmsgNo)
			sendmsgNo++
		}
	}
	syscalls = slices.CompactFunc(syscalls, func(a, b *ast.Call) bool {
		// We only compare the the system call names for cases where the same system call has different parameter names,
		// but share the same syzkaller type. NOTE:Change when we have better type extraction.
		return a.Name.Name == b.Name.Name
	})

	usedNetlink := make(map[string]bool)
	for _, node := range syscalls {
		if node.CallName == sendmsg && len(node.Args[1].Type.Args) == 2 && len(node.Args[1].Type.Args[1].Args) > 1 {
			policy := node.Args[1].Type.Args[1].Args[1].Ident
			usedNetlink[policy] = true
			_, isDefined := slices.BinarySearchFunc(structs, policy, func(a *ast.Struct, b string) int {
				return strings.Compare(a.Name.Name, b)
			})
			if !isDefined {
				continue
			}
		}
		nodes = append(nodes, node)
	}
	var netlinkNames []string
	for _, node := range structs {
		nodes = append(nodes, node)
		name := node.Name.Name
		if !usedNetlink[name] && !strings.HasSuffix(name, "$auto_record") {
			netlinkNames = append(netlinkNames, name)
		}
	}
	for i, structName := range netlinkNames {
		netlinkNames[i] = fmt.Sprintf("\tpolicy%v msghdr_auto[%v]\n", i, structName)
	}
	netlinkUnion := `
type msghdr_auto[POLICY] msghdr_netlink[netlink_msg_t[autogenerated_netlink, genlmsghdr, POLICY]]
resource autogenerated_netlink[int16]
syz_genetlink_get_family_id$auto(name ptr[in, string], fd sock_nl_generic) autogenerated_netlink
sendmsg$autorun(fd sock_nl_generic, msg ptr[in, auto_union], f flags[send_flags])
auto_union [
` + strings.Join(netlinkNames, "") + "]"
	eh := ast.LoggingHandler
	netlinkUnionParsed := ast.Parse([]byte(netlinkUnion), "", eh)
	if netlinkUnionParsed == nil {
		tool.Failf("parsing error")
	}
	nodes = append(nodes, netlinkUnionParsed.Nodes...)

	// These additional includes must be at the top (added after sorting), because other kernel headers
	// are broken and won't compile without these additional ones included first.
	header := `# Code generated by syz-declextract. DO NOT EDIT.

include <include/vdso/bits.h>
include <include/linux/types.h>
`
	desc := ast.Parse([]byte(header), "", eh)
	nodes = append(desc.Nodes, nodes...)
	return &ast.Description{Nodes: nodes}
}

func worker(outputs chan *output, files chan string, binary, compilationDatabase string) {
	for file := range files {
		out, err := exec.Command(binary, "-p", compilationDatabase, file).Output()
		var exitErr *exec.ExitError
		if err != nil && errors.As(err, &exitErr) && len(exitErr.Stderr) != 0 {
			err = fmt.Errorf("%s", exitErr.Stderr)
		}
		outputs <- &output{file, out, err}
	}
}

func renameSyscall(syscall *ast.Call, rename map[string][]string) []ast.Node {
	names := rename[syscall.CallName]
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
	for _, arch := range targets.List[targets.Linux] {
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
	const mainArch = targets.AMD64
	for syscall, descs := range syscalls {
		slices.SortFunc(descs, func(a, b desc) int {
			if (a.arch == mainArch) != (b.arch == mainArch) {
				if a.arch == mainArch {
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

func appendNodes(slice *[]ast.Node, interfaces *[]Interface, nodes []ast.Node,
	syscallNames map[string][]string, sourceDir, buildDir, file string, extractor *subsystem.Extractor) {
	for _, node := range nodes {
		switch node := node.(type) {
		case *ast.Call:
			// Some syscalls have different names and entry points and thus need to be renamed.
			// e.g. SYSCALL_DEFINE1(setuid16, old_uid_t, uid) is referred to in the .tbl file with setuid.
			*slice = append(*slice, renameSyscall(node, syscallNames)...)
		case *ast.Include:
			if file, err := filepath.Rel(sourceDir, filepath.Join(buildDir, node.File.Value)); err == nil {
				node.File.Value = file
			}
			*slice = append(*slice, node)
		case *ast.Comment:
			if !strings.HasPrefix(node.Text, "INTERFACE:") {
				*slice = append(*slice, node)
				continue
			}
			fields := strings.Fields(node.Text)
			files := []string{file}
			var crashes []*subsystem.Crash
			for _, file := range files {
				crashes = append(crashes, &subsystem.Crash{GuiltyPath: file})
			}
			var subsystems []string
			for _, s := range extractor.Extract(crashes) {
				subsystems = append(subsystems, s.Name)
			}
			slices.Sort(subsystems)
			iface := Interface{
				Type:             fields[1],
				Name:             fields[2],
				Files:            files,
				Subsystems:       subsystems,
				identifyingConst: fields[3],
			}
			if iface.Type == "SYSCALL" {
				for _, name := range syscallNames[iface.Name] {
					iface.Name = name
					iface.identifyingConst = "__NR_" + name
					*interfaces = append(*interfaces, iface)
				}
			} else {
				*interfaces = append(*interfaces, iface)
			}
		default:
			*slice = append(*slice, node)
		}
	}
}

func getTypeOrder(a ast.Node) int {
	switch a.(type) {
	case *ast.Comment:
		return 0
	case *ast.Include:
		return 1
	case *ast.IntFlags:
		return 2
	case *ast.Resource:
		return 3
	case *ast.TypeDef:
		return 4
	case *ast.Call:
		return 5
	case *ast.Struct:
		return 6
	case *ast.NewLine:
		return 7
	default:
		panic(fmt.Sprintf("unhandled type %T", a))
	}
}
